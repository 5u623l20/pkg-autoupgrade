/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
/*
 * services.c - post-upgrade service detection and restart.
 *
 * Two complementary paths find services that need attention after an upgrade:
 *
 * Path 1 (direct rc script ownership):
 *   For each rc script in /etc/rc.d/ and /usr/local/etc/rc.d/, call
 *   pkgdb_query_which() to find the owning package.  If that package is in
 *   plan->upgraded_names, the service is a candidate.
 *
 * Path 2 (stale mapping scan):
 *   Iterate all running processes via libprocstat.  For each process that has
 *   an executable VNODE mapping with no associated path (kve_path[0] == '\0'),
 *   the process is using a stale binary or shared library - the underlying
 *   file was replaced on disk (unlinked then rewritten) while the process kept
 *   its open mapping of the old inode.  If a script named after ki_comm
 *   exists in either rc directory, that service is added as a candidate.
 *
 *   This detects the shared-library case: e.g. openssl upgraded replaces
 *   libssl.so; nginx still maps the old inode.  nginx's ki_comm matches
 *   /usr/local/etc/rc.d/nginx so it is found without nginx itself being in
 *   the upgraded set.
 *
 * Once the candidate set is built (deduplicated), each entry is checked with
 * "service <name> onestatus".  Running services are either restarted
 * immediately (if the service is in the restart_services) or queued as a MOTD notice.
 */

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include <dirent.h>
#include <errno.h>
#include <libprocstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkg.h>

#include "pkg-autoupgrade.h"
#include "services.h"

#define	RC_DIR_BASE	"/etc/rc.d"
#define	RC_DIR_LOCAL	LOCALBASE "/etc/rc.d"

/* ------------------------------------------------------------------ */
/* Candidate set (simple dedup array) */

#define	CAND_MAX	512

struct cand_set {
	char	names[CAND_MAX][AU_MAX_NAME];
	int	n;
};

static bool
cand_contains(const struct cand_set *cs, const char *name)
{
	for (int i = 0; i < cs->n; i++) {
		if (strcmp(cs->names[i], name) == 0)
			return (true);
	}
	return (false);
}

static void
cand_add(struct cand_set *cs, const char *name)
{
	if (cs->n >= CAND_MAX || cand_contains(cs, name))
		return;
	strlcpy(cs->names[cs->n++], name, AU_MAX_NAME);
}

/* ------------------------------------------------------------------ */
/* Helper: is 'name' in the comma-separated restart_services? */

static bool
is_restart_allowed(const char *restart_services, const char *name)
{
	char	 buf[4096];
	char	*p, *tok, *end;

	if (restart_services == NULL || *restart_services == '\0')
		return (false);

	strlcpy(buf, restart_services, sizeof(buf));
	p = buf;
	while ((tok = strsep(&p, ",")) != NULL) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		end = tok + strlen(tok);
		while (end > tok && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		if (*tok != '\0' && strcmp(tok, name) == 0)
			return (true);
	}
	return (false);
}

/* ------------------------------------------------------------------ */
/* Helper: check if 'pkg_name' is in upgraded_names. */

static bool
was_upgraded(const struct au_upgrade_plan *plan, const char *pkg_name)
{
	for (int i = 0; i < plan->n_upgraded; i++) {
		if (strcmp(plan->upgraded_names[i], pkg_name) == 0)
			return (true);
	}
	return (false);
}

/* ------------------------------------------------------------------ */
/* Path 1: scan rc directories, resolve ownership via pkgdb_query_which. */

static void
scan_rc_dir(struct pkgdb *db, const struct au_upgrade_plan *plan,
    const char *rc_dir, struct cand_set *cs)
{
	DIR		*dh;
	struct dirent	*de;
	char		 path[MAXPATHLEN];
	struct pkgdb_it	*it;
	struct pkg	*pkg = NULL;
	const char	*pkg_name;

	dh = opendir(rc_dir);
	if (dh == NULL)
		return;

	while ((de = readdir(dh)) != NULL) {
		if (de->d_name[0] == '.')
			continue;

		(void)snprintf(path, sizeof(path), "%s/%s", rc_dir,
		    de->d_name);

		it = pkgdb_query_which(db, path, false);
		if (it == NULL)
			continue;

		pkg = NULL;
		if (pkgdb_it_next(it, &pkg, PKG_LOAD_BASIC) == EPKG_OK &&
		    pkg != NULL) {
			pkg_name = NULL;
			pkg_get(pkg, PKG_ATTR_NAME, &pkg_name);
			if (pkg_name != NULL && was_upgraded(plan, pkg_name))
				cand_add(cs, de->d_name);
			pkg_free(pkg);
		}
		pkgdb_it_free(it);
	}
	closedir(dh);
}

/* ------------------------------------------------------------------ */
/* Path 2: stale mapping scan via libprocstat. */

/*
 * rc_script_exists - return true if a script named 'comm' is present in
 * either rc directory.  The comm name from ki_comm may have been truncated
 * by the kernel to MAXCOMLEN (19) characters, so this is a prefix match for
 * names longer than MAXCOMLEN, but an exact match otherwise.
 */
static bool
rc_script_exists(const char *comm, char *script_name_out, size_t outsz)
{
	char		 path[MAXPATHLEN];
	struct stat	 sb;
	const char	*dirs[2] = { RC_DIR_LOCAL, RC_DIR_BASE };

	for (int i = 0; i < 2; i++) {
		(void)snprintf(path, sizeof(path), "%s/%s", dirs[i], comm);
		if (stat(path, &sb) == 0 && S_ISREG(sb.st_mode)) {
			strlcpy(script_name_out, comm, outsz);
			return (true);
		}
	}
	return (false);
}

static void
scan_stale_processes(struct cand_set *cs)
{
	struct procstat		*prstat;
	struct kinfo_proc	*procs;
	struct kinfo_vmentry	*vmaps;
	unsigned int		 pcnt, vmcnt, i, j;
	char			 svc[AU_MAX_NAME];

	prstat = procstat_open_sysctl();
	if (prstat == NULL) {
		pkg_emit_notice("autoupgrade: procstat_open_sysctl failed; "
		    "skipping stale-process scan");
		return;
	}

	procs = procstat_getprocs(prstat, KERN_PROC_PROC, 0, &pcnt);
	if (procs == NULL) {
		procstat_close(prstat);
		return;
	}

	for (i = 0; i < pcnt; i++) {
		struct kinfo_proc *proc = &procs[i];

		/* Kernel threads have no parent. */
		if (proc->ki_ppid == 0)
			continue;

		vmaps = procstat_getvmmap(prstat, proc, &vmcnt);
		if (vmaps == NULL)
			continue;

		for (j = 0; j < vmcnt; j++) {
			struct kinfo_vmentry *kve = &vmaps[j];

			/*
			 * An executable VNODE mapping with an empty path means
			 * the backing file was unlinked (replaced on disk) while
			 * this process held an open mapping of the old inode.
			 */
			if ((kve->kve_protection & KVME_PROT_EXEC) &&
			    kve->kve_type == KVME_TYPE_VNODE &&
			    kve->kve_path[0] == '\0') {
				if (rc_script_exists(proc->ki_comm,
				    svc, sizeof(svc)))
					cand_add(cs, svc);
				break;
			}
		}

		procstat_freevmmap(prstat, vmaps);
	}

	procstat_freeprocs(prstat, procs);
	procstat_close(prstat);
}

/* ------------------------------------------------------------------ */
/* Service status and restart via service(8). */

/*
 * svc_name_ok - return true if name contains only characters valid in an rc
 * script basename.  Rejects anything that could be a shell metacharacter so
 * that passing the name to system() is safe.
 */
static bool
svc_name_ok(const char *name)
{
	const char *p;

	if (name == NULL || *name == '\0')
		return (false);
	for (p = name; *p != '\0'; p++) {
		if ((*p >= 'a' && *p <= 'z') ||
		    (*p >= 'A' && *p <= 'Z') ||
		    (*p >= '0' && *p <= '9') ||
		    *p == '-' || *p == '_' || *p == '.')
			continue;
		return (false);
	}
	return (true);
}

static bool
service_is_running(const char *name)
{
	char	cmd[256];

	if (!svc_name_ok(name))
		return (false);
	(void)snprintf(cmd, sizeof(cmd), "service %s onestatus > /dev/null"
	    " 2>&1", name);
	return (system(cmd) == 0);
}

static void
service_restart(const char *name)
{
	char	cmd[256];
	int	rc;

	if (!svc_name_ok(name)) {
		pkg_emit_error("autoupgrade: refusing to restart service "
		    "with invalid name: %s", name);
		return;
	}
	(void)snprintf(cmd, sizeof(cmd), "service %s restart > /dev/null"
	    " 2>&1", name);
	rc = system(cmd);
	if (rc == 0) {
		pkg_emit_notice("autoupgrade: restarted service %s", name);
	} else {
		pkg_emit_error("autoupgrade: failed to restart service %s "
		    "(exit %d)", name, rc);
	}
}

/* ------------------------------------------------------------------ */

void
services_process(struct pkgdb *db, const struct au_config *cfg,
    const struct au_upgrade_plan *plan,
    char **notices, int *n_notices)
{
	struct cand_set	cs;
	char		notice[512];
	int		ni = 0;

	memset(&cs, 0, sizeof(cs));

	/* Path 1: rc scripts owned by upgraded packages. */
	scan_rc_dir(db, plan, RC_DIR_BASE,  &cs);
	scan_rc_dir(db, plan, RC_DIR_LOCAL, &cs);

	/* Path 2: processes with stale vnode mappings. */
	scan_stale_processes(&cs);

	/* Evaluate each candidate. */
	for (int i = 0; i < cs.n; i++) {
		const char *svc = cs.names[i];

		if (!service_is_running(svc))
			continue;

		if (is_restart_allowed(cfg->restart_services, svc)) {
			service_restart(svc);
		} else if (ni < AU_MAX_NOTICES) {
			(void)snprintf(notice, sizeof(notice),
			    "Service needs restart after upgrade: %s "
			    "(not in AU_RESTART_SERVICES)", svc);
			notices[ni] = strdup(notice);
			if (notices[ni] != NULL)
				ni++;
		}
	}

	*n_notices = ni;
}
