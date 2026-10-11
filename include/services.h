/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
#ifndef AU_SERVICES_H
#define	AU_SERVICES_H

struct pkgdb;
struct au_config;
struct au_upgrade_plan;

/*
 * services_process - full post-upgrade service pipeline.
 *
 * 1. Scan /etc/rc.d/ and /usr/local/etc/rc.d/ for scripts owned by any
 *    package in plan->upgraded_names (via pkgdb_query_which).
 * 2. Scan all running processes for stale executable/library vnode mappings
 *    (embedded checkrestart logic via libprocstat); match process comm names
 *    to rc script basenames.
 * 3. For each candidate service found by either path:
 *    - if running and allowed in cfg: restart it via service(8).
 *    - if running and not allowed: append a notice to notices[].
 *
 * notices[] must have room for at least AU_MAX_NOTICES pointers to
 * malloc'd strings.  The caller owns and must free them.
 * *n_notices is set to the number of entries written.
 */
void	services_process(struct pkgdb *db, const struct au_config *cfg,
	    const struct au_upgrade_plan *plan,
	    char **notices, int *n_notices);

#endif /* AU_SERVICES_H */
