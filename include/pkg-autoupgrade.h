/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
#ifndef PKG_AUTOUPGRADE_H
#define	PKG_AUTOUPGRADE_H

#include <stdbool.h>
#include <pkg.h>

#define	AU_VERSION	"1.0.0"
#define	AU_PLUGIN_NAME	"autoupgrade"

/*
 * Filesystem paths used by the plugin.
 */
#define	AU_STATE_DIR		"/var/db/pkg-autoupgrade"
#define	AU_STATE_NOTICES	AU_STATE_DIR "/notices"
#define	AU_REBOOT_PENDING	AU_STATE_DIR "/reboot-pending"
#define	AU_MOTD_PATH		"/var/run/motd"
#define	AU_MOTD_BEGIN		"# --- pkg-autoupgrade begin ---"
#define	AU_MOTD_END		"# --- pkg-autoupgrade end ---"

/*
 * Compile-time array bounds.  Systems with unusually large pkg sets may
 * need these increased, but the defaults cover any practical deployment.
 */
#define	AU_MAX_UPGRADED		1024	/* distinct packages in one upgrade run */
#define	AU_MAX_NOTICES		128	/* pending restart/reboot notices */
#define	AU_MAX_NAME		256	/* package or service name length */

struct au_config {
	bool	allow_base_upgrade;
	char	base_repos[1024];	/* comma-separated repo names */
	bool	be_enabled;
	char	be_prefix[64];
	int	be_keep;		/* max auto BEs to retain */
	bool	allow_reboot;
	char	reboot_time[16];	/* "now" or "HH:MM" */
	bool	reboot_if_users;	/* reboot even if users are logged in */
	char	restart_services[4096];	/* comma-separated service names */
	bool	ufs_kernel_backup;
	bool	only_vulnerable;	/* upgrade only packages with known vulns */
	char	blocklist[4096];	/* comma-separated POSIX ERE patterns */
	bool	autoremove;		/* run pkg autoremove after upgrade */
	char	mail_to[256];		/* recipient; empty = disabled */
	char	mail_report[16];	/* "always", "on-error", "on-change" */
};

/*
 * Upgrade plan filled by scanning the job iterator before pkg_jobs_apply().
 * kernel_upgrade is set if any package with a name starting with
 * "FreeBSD-kernel" is in the upgrade set.
 */
struct au_upgrade_plan {
	bool	kernel_upgrade;
	char	kernel_pkg[AU_MAX_NAME];
	char	upgraded_names[AU_MAX_UPGRADED][AU_MAX_NAME];
	int	n_upgraded;
	char	blocked_names[AU_MAX_UPGRADED][AU_MAX_NAME];
	int	n_blocked;
};

extern struct pkg_plugin	*g_plugin;
extern struct au_config		 g_config;

#endif /* PKG_AUTOUPGRADE_H */
