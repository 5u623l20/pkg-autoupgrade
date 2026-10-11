/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
/*
 * config.c - UCL configuration parsing.
 *
 * config_register_keys() declares all keys and their compiled-in defaults
 * via pkg_plugin_conf_add().  pkg_plugin_parse() then overlays those with
 * values from /usr/local/etc/pkg/autoupgrade.conf.  config_load() reads the
 * merged object into g_config.
 *
 * All list-valued options (base_repos, restart_services) are stored as
 * comma-separated strings; callers split them with strsep().
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <pkg.h>

#include "pkg-autoupgrade.h"
#include "config.h"

#define	DEFAULT_ALLOW_BASE	"false"
#define	DEFAULT_BASE_REPOS	"FreeBSD-base"
#define	DEFAULT_BE_ENABLED	"true"
#define	DEFAULT_BE_PREFIX	"pre-autoupgrade"
#define	DEFAULT_BE_KEEP		"5"
#define	DEFAULT_ALLOW_REBOOT	"false"
#define	DEFAULT_RESTART_SERVICES	""
#define	DEFAULT_UFS_BACKUP	"true"
#define	DEFAULT_ONLY_VULN	"false"
#define	DEFAULT_BLOCKLIST	""
#define	DEFAULT_AUTOREMOVE	"false"
#define	DEFAULT_REBOOT_TIME	"now"
#define	DEFAULT_REBOOT_USERS	"false"
#define	DEFAULT_MAIL_TO		""
#define	DEFAULT_MAIL_REPORT	"on-change"

int
config_register_keys(struct pkg_plugin *p)
{
	if (pkg_plugin_conf_add(p, PKG_BOOL,   "AU_ALLOW_BASE_UPGRADE",
	    DEFAULT_ALLOW_BASE) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_STRING, "AU_BASE_REPOS",
	    DEFAULT_BASE_REPOS) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_BOOL,   "AU_BE_ENABLED",
	    DEFAULT_BE_ENABLED) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_STRING, "AU_BE_PREFIX",
	    DEFAULT_BE_PREFIX) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_INT,    "AU_BE_KEEP",
	    DEFAULT_BE_KEEP) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_BOOL,   "AU_ALLOW_REBOOT",
	    DEFAULT_ALLOW_REBOOT) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_STRING, "AU_RESTART_SERVICES",
	    DEFAULT_RESTART_SERVICES) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_BOOL,   "AU_UFS_KERNEL_BACKUP",
	    DEFAULT_UFS_BACKUP) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_BOOL,   "AU_ONLY_UPGRADE_VULNERABLE_PKG",
	    DEFAULT_ONLY_VULN) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_STRING, "AU_BLOCKLISTED_PACKAGES",
	    DEFAULT_BLOCKLIST) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_BOOL,   "AU_AUTOREMOVE",
	    DEFAULT_AUTOREMOVE) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_STRING, "AU_REBOOT_TIME",
	    DEFAULT_REBOOT_TIME) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_BOOL,   "AU_REBOOT_IF_USERS_LOGGED_IN",
	    DEFAULT_REBOOT_USERS) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_STRING, "AU_MAIL_TO",
	    DEFAULT_MAIL_TO) != EPKG_OK)
		goto fail;
	if (pkg_plugin_conf_add(p, PKG_STRING, "AU_MAIL_REPORT",
	    DEFAULT_MAIL_REPORT) != EPKG_OK)
		goto fail;
	return (EPKG_OK);
fail:
	pkg_plugin_error(p, "autoupgrade: failed to register config keys");
	return (EPKG_FATAL);
}

static bool
reboot_time_ok(const char *s)
{
	int h, m, n;

	if (strcmp(s, "now") == 0)
		return (true);
	n = sscanf(s, "%d:%d", &h, &m);
	return (n == 2 && h >= 0 && h <= 23 && m >= 0 && m <= 59);
}

static bool
mail_to_ok(const char *s)
{
	const char *p;

	for (p = s; *p != '\0'; p++) {
		if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f)
			return (false);
	}
	return (true);
}

int
config_load(struct pkg_plugin *p, struct au_config *cfg)
{
	const pkg_object	*conf, *obj;
	const char		*key, *val;
	pkg_iter		 it = NULL;

	cfg->allow_base_upgrade = false;
	strlcpy(cfg->base_repos, DEFAULT_BASE_REPOS, sizeof(cfg->base_repos));
	cfg->be_enabled = true;
	strlcpy(cfg->be_prefix, DEFAULT_BE_PREFIX, sizeof(cfg->be_prefix));
	cfg->be_keep = 5;
	cfg->allow_reboot = false;
	strlcpy(cfg->reboot_time, DEFAULT_REBOOT_TIME, sizeof(cfg->reboot_time));
	cfg->reboot_if_users = false;
	cfg->restart_services[0] = '\0';
	cfg->ufs_kernel_backup = true;
	cfg->only_vulnerable = false;
	cfg->blocklist[0] = '\0';
	cfg->autoremove = false;
	cfg->mail_to[0] = '\0';
	strlcpy(cfg->mail_report, DEFAULT_MAIL_REPORT, sizeof(cfg->mail_report));

	conf = pkg_plugin_conf(p);
	if (conf == NULL)
		return (EPKG_OK);

	while ((obj = pkg_object_iterate(conf, &it)) != NULL) {
		key = pkg_object_key(obj);
		if (key == NULL)
			continue;

		if (strcmp(key, "AU_ALLOW_BASE_UPGRADE") == 0) {
			cfg->allow_base_upgrade = pkg_object_bool(obj);

		} else if (strcmp(key, "AU_BASE_REPOS") == 0) {
			val = pkg_object_string(obj);
			if (val != NULL)
				strlcpy(cfg->base_repos, val,
				    sizeof(cfg->base_repos));

		} else if (strcmp(key, "AU_BE_ENABLED") == 0) {
			cfg->be_enabled = pkg_object_bool(obj);

		} else if (strcmp(key, "AU_BE_PREFIX") == 0) {
			val = pkg_object_string(obj);
			if (val != NULL && *val != '\0') {
				if (strlcpy(cfg->be_prefix, val,
				    sizeof(cfg->be_prefix)) >=
				    sizeof(cfg->be_prefix)) {
					pkg_plugin_error(p,
					    "autoupgrade: AU_BE_PREFIX too long"
					    " (max %zu chars)",
					    sizeof(cfg->be_prefix) - 1);
					return (EPKG_FATAL);
				}
			}

		} else if (strcmp(key, "AU_BE_KEEP") == 0) {
			cfg->be_keep = (int)pkg_object_int(obj);
			if (cfg->be_keep < 1) {
				pkg_plugin_error(p,
				    "autoupgrade: AU_BE_KEEP must be >= 1");
				return (EPKG_FATAL);
			}

		} else if (strcmp(key, "AU_ALLOW_REBOOT") == 0) {
			cfg->allow_reboot = pkg_object_bool(obj);

		} else if (strcmp(key, "AU_RESTART_SERVICES") == 0) {
			val = pkg_object_string(obj);
			if (val != NULL)
				strlcpy(cfg->restart_services, val,
				    sizeof(cfg->restart_services));

		} else if (strcmp(key, "AU_UFS_KERNEL_BACKUP") == 0) {
			cfg->ufs_kernel_backup = pkg_object_bool(obj);

		} else if (strcmp(key, "AU_ONLY_UPGRADE_VULNERABLE_PKG") == 0) {
			cfg->only_vulnerable = pkg_object_bool(obj);

		} else if (strcmp(key, "AU_BLOCKLISTED_PACKAGES") == 0) {
			val = pkg_object_string(obj);
			if (val != NULL)
				strlcpy(cfg->blocklist, val,
				    sizeof(cfg->blocklist));

		} else if (strcmp(key, "AU_AUTOREMOVE") == 0) {
			cfg->autoremove = pkg_object_bool(obj);

		} else if (strcmp(key, "AU_REBOOT_TIME") == 0) {
			val = pkg_object_string(obj);
			if (val != NULL && *val != '\0') {
				if (!reboot_time_ok(val)) {
					pkg_plugin_error(p,
					    "autoupgrade: AU_REBOOT_TIME must be "
					    "'now' or 'HH:MM'");
					return (EPKG_FATAL);
				}
				strlcpy(cfg->reboot_time, val,
				    sizeof(cfg->reboot_time));
			}

		} else if (strcmp(key, "AU_REBOOT_IF_USERS_LOGGED_IN") == 0) {
			cfg->reboot_if_users = pkg_object_bool(obj);

		} else if (strcmp(key, "AU_MAIL_TO") == 0) {
			val = pkg_object_string(obj);
			if (val != NULL && *val != '\0') {
				if (!mail_to_ok(val)) {
					pkg_plugin_error(p,
					    "autoupgrade: AU_MAIL_TO contains "
					    "invalid characters");
					return (EPKG_FATAL);
				}
				strlcpy(cfg->mail_to, val,
				    sizeof(cfg->mail_to));
			}

		} else if (strcmp(key, "AU_MAIL_REPORT") == 0) {
			val = pkg_object_string(obj);
			if (val != NULL && *val != '\0') {
				if (strcmp(val, "always") != 0 &&
				    strcmp(val, "on-error") != 0 &&
				    strcmp(val, "on-change") != 0) {
					pkg_plugin_error(p,
					    "autoupgrade: AU_MAIL_REPORT must "
					    "be 'always', 'on-error', or "
					    "'on-change'");
					return (EPKG_FATAL);
				}
				strlcpy(cfg->mail_report, val,
				    sizeof(cfg->mail_report));
			}
		}
	}

	return (EPKG_OK);
}
