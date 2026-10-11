/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
/*
 * be_support.c - boot environment and kernel backup safety net.
 *
 * ZFS root: create a libbe(3) boot environment before the upgrade job runs.
 * Prune excess BEs with the same prefix afterwards.
 *
 * UFS root: if a kernel package is being upgraded, rename /boot/kernel to
 * /boot/kernel.old.  The FreeBSD boot loader can boot the old kernel from
 * that path via "Boot Older Kernel" in the loader menu or nextboot(8).
 */

#include <sys/param.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

/*
 * be_compat.h defines uint_t / boolean_t / uchar_t / hrtime_t for user-space
 * and then includes <be.h>.  Any file needing libbe must include this instead
 * of <be.h> directly.
 */
typedef unsigned int	uint_t;
typedef unsigned int	boolean_t;
typedef unsigned char	uchar_t;
typedef long long	hrtime_t;
#include <stdarg.h>
#include <be.h>

#include <pkg.h>

#include "pkg-autoupgrade.h"
#include "be_support.h"

/* Maximum generated BE name: prefix (63) + "-" + "YYYYMMDDTHHMMSS" (15) */
#define	BE_NAME_LEN	128

bool
be_is_zfs_root(void)
{
	struct statfs	sfs;

	if (statfs("/", &sfs) != 0)
		return (false);
	return (strcmp(sfs.f_fstypename, "zfs") == 0);
}

static void
generate_be_name(const char *prefix, char *buf, size_t bufsz)
{
	time_t		now;
	struct tm	tm;

	time(&now);
	localtime_r(&now, &tm);
	(void)snprintf(buf, bufsz, "%s-%04d%02d%02dT%02d%02d%02d",
	    prefix,
	    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
	    tm.tm_hour, tm.tm_min, tm.tm_sec);
}

/*
 * Candidate BE for pruning.  Carries the name and ZFS creation timestamp so
 * we can sort oldest-first and delete the excess.
 */
struct be_cand {
	char		name[BE_NAME_LEN];
	uint64_t	created;	/* seconds since epoch */
};

static int
be_cand_cmp(const void *a, const void *b)
{
	const struct be_cand	*ca = a, *cb = b;

	if (ca->created < cb->created)
		return (-1);
	if (ca->created > cb->created)
		return (1);
	return (0);
}

/*
 * Prune BEs whose names begin with "<prefix>-" to at most keep entries.
 * Operates best-effort: failures are logged but never abort the caller.
 */
static void
be_prune(libbe_handle_t *hdl, const char *prefix, int keep)
{
	nvlist_t	*props = NULL;
	nvpair_t	*pair;
	struct be_cand	*cands = NULL;
	int		 n = 0, cap = 0;
	size_t		 pfxlen;

	pfxlen = strlen(prefix);

	if (be_prop_list_alloc(&props) != 0) {
		pkg_emit_notice("autoupgrade: be_prop_list_alloc failed; "
		    "skipping BE prune");
		return;
	}

	if (be_get_bootenv_props(hdl, props) != BE_ERR_SUCCESS) {
		pkg_emit_notice("autoupgrade: be_get_bootenv_props failed; "
		    "skipping BE prune");
		be_prop_list_free(props);
		return;
	}

	for (pair = nvlist_next_nvpair(props, NULL);
	    pair != NULL;
	    pair = nvlist_next_nvpair(props, pair)) {
		const char	*bename, *creation_str;
		nvlist_t	*be_props;
		char		*endptr;
		long long	 val;

		bename = nvpair_name(pair);
		/* Accept only "<prefix>-..." to avoid matching user BEs. */
		if (strncmp(bename, prefix, pfxlen) != 0 ||
		    bename[pfxlen] != '-')
			continue;

		if (nvpair_value_nvlist(pair, &be_props) != 0)
			continue;

		/* libbe stores creation as a decimal Unix epoch string. */
		if (nvlist_lookup_string(be_props, "creation",
		    &creation_str) != 0)
			continue;

		errno = 0;
		val = strtoll(creation_str, &endptr, 10);
		if (errno != 0 || endptr == creation_str ||
		    *endptr != '\0' || val < 0)
			continue;

		if (n >= cap) {
			int		 newcap = (cap == 0) ? 8 : cap * 2;
			struct be_cand	*tmp;

			tmp = realloc(cands,
			    (size_t)newcap * sizeof(*cands));
			if (tmp == NULL) {
				pkg_emit_notice("autoupgrade: OOM in be_prune; "
				    "skipping prune");
				goto out;
			}
			cands = tmp;
			cap = newcap;
		}
		strlcpy(cands[n].name, bename, sizeof(cands[n].name));
		cands[n].created = (uint64_t)val;
		n++;
	}

	if (n <= keep)
		goto out;

	qsort(cands, (size_t)n, sizeof(*cands), be_cand_cmp);

	for (int i = 0; i < n - keep; i++) {
		if (be_destroy(hdl, cands[i].name,
		    BE_DESTROY_AUTOORIGIN) == BE_ERR_SUCCESS) {
			pkg_emit_notice("autoupgrade: pruned BE %s",
			    cands[i].name);
			syslog(LOG_NOTICE,
			    "autoupgrade: pruned BE %s", cands[i].name);
		} else {
			pkg_emit_notice("autoupgrade: failed to prune BE %s",
			    cands[i].name);
		}
	}

out:
	free(cands);
	be_prop_list_free(props);
}

int
be_create_snapshot(const struct au_config *cfg)
{
	libbe_handle_t	*hdl;
	char		 name[BE_NAME_LEN];
	int		 ret = 0;

	hdl = libbe_init(NULL);
	if (hdl == NULL) {
		pkg_emit_error("autoupgrade: libbe_init failed");
		return (-1);
	}

	generate_be_name(cfg->be_prefix, name, sizeof(name));

	if (be_create(hdl, name) != 0) {
		pkg_emit_error("autoupgrade: be_create(%s) failed: %s",
		    name, libbe_error_description(hdl));
		ret = -1;
		goto out;
	}

	pkg_emit_notice("autoupgrade: created boot environment %s", name);
	syslog(LOG_NOTICE, "autoupgrade: created boot environment %s", name);

	be_prune(hdl, cfg->be_prefix, cfg->be_keep);

out:
	libbe_close(hdl);
	return (ret);
}

/*
 * Recursively remove a directory tree via nftw().  Used to clear out the
 * previous /boot/kernel.old before renaming the current kernel into place.
 *
 * nftw() with FTW_DEPTH visits children before parents, and FTW_MOUNT keeps
 * us on the same filesystem.  We unlink files and rmdir directories.
 */
static int
rm_tree_fn(const char *path, const struct stat *sb __unused,
    int type, struct FTW *ftwbuf __unused)
{
	if (type == FTW_DP)
		return (rmdir(path) == 0 ? 0 : -1);
	return (unlink(path) == 0 ? 0 : -1);
}

static int
rm_tree(const char *path)
{
	return (nftw(path, rm_tree_fn, 16, FTW_DEPTH | FTW_MOUNT | FTW_PHYS));
}

int
ufs_backup_kernel(void)
{
	struct stat	sb;

	if (stat("/boot/kernel.old", &sb) == 0) {
		if (rm_tree("/boot/kernel.old") != 0) {
			pkg_emit_error("autoupgrade: failed to remove "
			    "/boot/kernel.old: %s", strerror(errno));
			return (-1);
		}
	} else if (errno != ENOENT) {
		pkg_emit_error("autoupgrade: stat(/boot/kernel.old) failed: %s",
		    strerror(errno));
		return (-1);
	}

	if (rename("/boot/kernel", "/boot/kernel.old") != 0) {
		pkg_emit_error("autoupgrade: rename /boot/kernel -> "
		    "/boot/kernel.old failed: %s", strerror(errno));
		return (-1);
	}

	pkg_emit_notice("autoupgrade: UFS kernel backup: "
	    "/boot/kernel -> /boot/kernel.old");
	syslog(LOG_NOTICE, "autoupgrade: UFS kernel backup: "
	    "/boot/kernel -> /boot/kernel.old");
	return (0);
}

int
be_prepare_safety_net(const struct au_config *cfg, bool kernel_upgrade)
{
	if (!cfg->be_enabled)
		return (0);

	if (be_is_zfs_root())
		return (be_create_snapshot(cfg));

	/*
	 * UFS root.  Only back up the kernel directory since there is no
	 * snapshot mechanism.  Proceeding without a backup when the option
	 * is disabled is the admin's explicit choice.
	 */
	if (kernel_upgrade && cfg->ufs_kernel_backup)
		return (ufs_backup_kernel());

	return (0);
}
