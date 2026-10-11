/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
#ifndef AU_UPGRADE_H
#define	AU_UPGRADE_H

struct pkgdb;
struct au_config;
struct au_upgrade_plan;

/*
 * upgrade_run - update repo catalogues, build an upgrade job for all
 * allowed repos, run the safety net (BE or kernel backup), apply the job,
 * and populate *plan with the set of upgraded package names.
 *
 * Returns 0 if upgrades were applied, 1 if there was nothing to do,
 * -1 on fatal error.
 */
int	upgrade_run(struct pkgdb *db, const struct au_config *cfg,
	    struct au_upgrade_plan *plan);

#endif /* AU_UPGRADE_H */
