/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
/*
 * pkg-autoupgrade.c - plugin entry points and command dispatch.
 *
 * Exports the pkg(8) plugin API symbols pkg_plugin_init and
 * pkg_plugin_shutdown, plus the command-provider symbols
 * pkg_register_cmd_count and pkg_register_cmd which register the
 * "autoupgrade" subcommand.
 *
 * Flow of exec_autoupgrade():
 *   1. Open the package database.
 *   2. Run upgrade_run(): update repos, build job, detect kernel upgrade,
 *      create safety net (BE or /boot/kernel backup), apply.
 *   3. Run services_process(): find upgraded-service candidates via rc dir
 *      scan and stale-mapping scan; restart allowed ones; queue notices.
 *   4. If a kernel was upgraded and we are not in a jail:
 *        - AU_ALLOW_REBOOT true  -> reboot(2)
 *        - AU_ALLOW_REBOOT false -> queue notice
 *   5. motd_update(): stamp /var/run/motd and persist state for boot.
 */

#include <sys/param.h>
#include <sys/reboot.h>
#include <sys/sysctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utmpx.h>

#include <pkg.h>

#include "pkg-autoupgrade.h"
#include "config.h"
#include "upgrade.h"
#include "services.h"
#include "motd.h"
#include "mail.h"

struct pkg_plugin	*g_plugin;
struct au_config	 g_config;

/* Exported plugin symbols discovered by pkg via dlsym. */
int	pkg_register_cmd_count(void);
int	pkg_register_cmd(int idx, const char **name, const char **desc,
	    int (**exec)(int argc, char **argv));
int	pkg_plugin_init(struct pkg_plugin *p);
int	pkg_plugin_shutdown(struct pkg_plugin *p);

/* ------------------------------------------------------------------ */

static bool
running_in_jail(void)
{
	int	jailed = 0;
	size_t	len = sizeof(jailed);

	(void)sysctlbyname("security.jail.jailed", &jailed, &len, NULL, 0);
	return (jailed != 0);
}

static bool
users_are_logged_in(void)
{
	struct utmpx	*ut;
	bool		 found = false;

	setutxent();
	while ((ut = getutxent()) != NULL) {
		if (ut->ut_type == USER_PROCESS) {
			found = true;
			break;
		}
	}
	endutxent();
	return (found);
}

/*
 * do_reboot - reboot the system at the configured time.
 *
 * reboot_time is either "now" (use reboot(2) directly) or an "HH:MM"
 * string (schedule via shutdown(8) so the admin has a warning window).
 * The value is validated in config_load() so no further checks are needed.
 */
static void
do_reboot(const char *reboot_time)
{
	char cmd[128];

	if (reboot_time[0] == '\0' || strcmp(reboot_time, "now") == 0) {
		sync();
		reboot(RB_AUTOBOOT);
		/* NOTREACHED */
	}

	/*
	 * shutdown(8) broadcasts a wall message; the "pkg-autoupgrade" arg
	 * becomes the reason string visible to logged-in users.
	 */
	snprintf(cmd, sizeof(cmd),
	    "/sbin/shutdown -r %s 'kernel upgraded by pkg-autoupgrade'",
	    reboot_time);
	(void)system(cmd);
}

/* ------------------------------------------------------------------ */

static int
exec_autoupgrade(int argc __unused, char **argv __unused)
{
	struct pkgdb		*db = NULL;
	struct au_upgrade_plan	 plan;
	char			*notices[AU_MAX_NOTICES];
	int			 n_notices = 0;
	int			 upgrade_ret;
	int			 ret = EXIT_FAILURE;
	bool			 had_error = false;
	char			 reboot_notice[256];

	if (geteuid() != 0) {
		pkg_emit_error("autoupgrade: must run as root");
		return (EXIT_FAILURE);
	}

	if (pkgdb_open(&db, PKGDB_REMOTE) != EPKG_OK) {
		pkg_emit_error("autoupgrade: cannot open package database");
		return (EXIT_FAILURE);
	}

	if (pkgdb_obtain_lock(db, PKGDB_LOCK_ADVISORY) != EPKG_OK) {
		pkg_emit_error("autoupgrade: cannot obtain database lock");
		pkgdb_close(db);
		return (EXIT_FAILURE);
	}

	upgrade_ret = upgrade_run(db, &g_config, &plan);

	if (upgrade_ret == 1) {
		/* Nothing to upgrade; keep any existing MOTD notices. */
		ret = EXIT_SUCCESS;
		goto cleanup;
	}
	if (upgrade_ret != 0) {
		had_error = true;
		goto send_mail;
	}

	/* Post-upgrade: service restart and stale-process scan. */
	services_process(db, &g_config, &plan, notices, &n_notices);

	/*
	 * Reboot handling: only when a kernel package was upgraded outside a
	 * jail.  If AU_ALLOW_REBOOT is false, or users are logged in and
	 * AU_REBOOT_IF_USERS_LOGGED_IN is false, queue a MOTD notice instead.
	 */
	if (plan.kernel_upgrade && !running_in_jail()) {
		if (g_config.allow_reboot) {
			bool users_present = users_are_logged_in();

			if (users_present && !g_config.reboot_if_users) {
				(void)snprintf(reboot_notice,
				    sizeof(reboot_notice),
				    "System reboot required: kernel upgraded "
				    "(%s); deferred — users are logged in",
				    plan.kernel_pkg);
				pkg_emit_notice("autoupgrade: reboot deferred; "
				    "users are logged in");
			} else {
				/*
				 * Flush state before reboot.  For a scheduled
				 * reboot (HH:MM) we fall through to the normal
				 * cleanup path; shutdown(8) handles the delay.
				 */
				pkg_emit_notice("autoupgrade: kernel upgraded "
				    "(%s); rebooting (%s)", plan.kernel_pkg,
				    g_config.reboot_time);
				motd_update(notices, n_notices);
				mail_send(&g_config, &plan,
				    (const char * const *)notices, n_notices,
				    false);
				for (int i = 0; i < n_notices; i++)
					free(notices[i]);
				pkgdb_release_lock(db, PKGDB_LOCK_ADVISORY);
				pkgdb_close(db);
				do_reboot(g_config.reboot_time);
				/* NOTREACHED for "now"; falls through for HH:MM */
				return (EXIT_SUCCESS);
			}
		} else {
			(void)snprintf(reboot_notice, sizeof(reboot_notice),
			    "System reboot required: kernel was upgraded (%s)",
			    plan.kernel_pkg);
			pkg_emit_notice("autoupgrade: kernel upgraded (%s); "
			    "manual reboot required (AU_ALLOW_REBOOT is false)",
			    plan.kernel_pkg);
		}

		/* Queue a reboot notice and create the pending flag. */
		if (n_notices < AU_MAX_NOTICES) {
			notices[n_notices] = strdup(reboot_notice);
			if (notices[n_notices] != NULL)
				n_notices++;
		}
		{
			int fd = open(AU_REBOOT_PENDING,
			    O_CREAT | O_WRONLY | O_TRUNC, 0644);
			if (fd >= 0)
				close(fd);
		}
	}

	motd_update(notices, n_notices);
	ret = EXIT_SUCCESS;

send_mail:
	mail_send(&g_config, &plan,
	    (const char * const *)notices, n_notices, had_error);

cleanup:
	for (int i = 0; i < n_notices; i++)
		free(notices[i]);
	pkgdb_release_lock(db, PKGDB_LOCK_ADVISORY);
	pkgdb_close(db);
	return (ret);
}

/* ------------------------------------------------------------------ */
/* pkg(8) command-provider symbols. */

int
pkg_register_cmd_count(void)
{
	return (1);
}

int
pkg_register_cmd(int idx, const char **name, const char **desc,
    int (**exec)(int argc, char **argv))
{
	if (idx != 0)
		return (EPKG_FATAL);

	*name = "autoupgrade";
	*desc = "Automated system upgrade with BE safety net and service restart";
	*exec = exec_autoupgrade;
	return (EPKG_OK);
}

/* ------------------------------------------------------------------ */
/* pkg(8) plugin lifecycle. */

int
pkg_plugin_init(struct pkg_plugin *p)
{
	g_plugin = p;

	pkg_plugin_set(p, PKG_PLUGIN_NAME,    AU_PLUGIN_NAME);
	pkg_plugin_set(p, PKG_PLUGIN_DESC,
	    "Automated upgrades: BE safety net, service restart, MOTD notices");
	pkg_plugin_set(p, PKG_PLUGIN_VERSION, AU_VERSION);

	if (config_register_keys(p) != EPKG_OK)
		return (EPKG_FATAL);

	if (pkg_plugin_parse(p) != EPKG_OK)
		return (EPKG_FATAL);

	if (config_load(p, &g_config) != EPKG_OK)
		return (EPKG_FATAL);

	return (EPKG_OK);
}

int
pkg_plugin_shutdown(struct pkg_plugin *p __unused)
{
	return (EPKG_OK);
}
