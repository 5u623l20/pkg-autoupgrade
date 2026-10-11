/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
/*
 * upgrade.c - pkg job lifecycle for automated upgrades.
 *
 * Repo filtering:
 *   If AU_ALLOW_BASE_UPGRADE is false, repos whose names appear in
 *   AU_BASE_REPOS (comma-separated) are excluded from the upgrade job.
 *   This prevents pkgbase (kernel, world) packages from being touched
 *   during an automatic run.  When AU_ALLOW_BASE_UPGRADE is true, all
 *   configured repos are upgraded.
 *
 * Kernel detection:
 *   Any package whose name begins with "FreeBSD-kernel" is treated as a
 *   kernel package.  The plan->kernel_upgrade flag is set when such a
 *   package is found in the job iterator, triggering the safety net in
 *   be_support.c before the job is applied.
 */

#include <regex.h>
#include <stdlib.h>
#include <string.h>

#include <pkg.h>

#include "pkg-autoupgrade.h"
#include "audit.h"
#include "be_support.h"
#include "upgrade.h"

/*
 * repo_is_excluded - return true if name appears in the comma-separated
 * base_repos string.  Comparison is case-sensitive; strip leading/trailing
 * whitespace from each token.
 */
static bool
repo_is_excluded(const char *base_repos, const char *name)
{
	char		 buf[1024];
	char		*p, *tok, *end;

	if (base_repos == NULL || *base_repos == '\0')
		return (false);

	strlcpy(buf, base_repos, sizeof(buf));
	p = buf;
	while ((tok = strsep(&p, ",")) != NULL) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		end = tok + strlen(tok);
		while (end > tok && (end[-1] == ' ' || end[-1] == '\t'))
			*--end = '\0';
		if (*tok == '\0')
			continue;
		if (strcmp(tok, name) == 0)
			return (true);
	}
	return (false);
}

/*
 * build_repo_list - populate *reponames with the names of all enabled repos
 * that are not excluded by cfg->base_repos.  Returns the number of repos
 * added.  Caller must vec_free(reponames) when done.
 */
static int
build_repo_list(const struct au_config *cfg, c_charv_t *reponames)
{
	struct pkg_repo	*repo = NULL;
	int		 n = 0;

	while (pkg_repos(&repo) != EPKG_END) {
		if (!pkg_repo_enabled(repo))
			continue;
		if (!cfg->allow_base_upgrade &&
		    repo_is_excluded(cfg->base_repos, pkg_repo_name(repo)))
			continue;
		vec_push(reponames, pkg_repo_name(repo));
		n++;
	}
	return (n);
}

/*
 * update_repos - refresh catalogs for every repo in reponames.
 * Non-fatal: a single repo failure is logged but does not abort.
 */
static void
update_repos(c_charv_t *reponames)
{
	struct pkg_repo	*repo = NULL;

	while (pkg_repos(&repo) != EPKG_END) {
		if (!pkg_repo_enabled(repo))
			continue;
		/* Only update repos that will be in the job. */
		bool found = false;
		vec_foreach(*reponames, i) {
			if (strcmp(reponames->d[i], pkg_repo_name(repo)) == 0) {
				found = true;
				break;
			}
		}
		if (!found)
			continue;
		if (pkg_update(repo, false) != EPKG_OK)
			pkg_emit_notice("autoupgrade: failed to update repo %s",
			    pkg_repo_name(repo));
	}
}

/*
 * scan_plan - iterate the solved job and populate *plan.
 *
 * For each PKG_SOLVED_UPGRADE or PKG_SOLVED_INSTALL entry, record the new
 * package name.  Set plan->kernel_upgrade if any name starts with
 * "FreeBSD-kernel".
 */
static void
scan_plan(struct pkg_jobs *jobs, struct au_upgrade_plan *plan)
{
	struct pkg	*new_pkg, *old_pkg;
	void		*iter = NULL;
	int		 type;
	const char	*name;

	while (pkg_jobs_iter(jobs, &iter, &new_pkg, &old_pkg, &type)) {
		if (type != PKG_SOLVED_UPGRADE &&
		    type != PKG_SOLVED_INSTALL &&
		    type != PKG_SOLVED_UPGRADE_INSTALL)
			continue;
		if (new_pkg == NULL)
			continue;

		name = NULL;
		pkg_get(new_pkg, PKG_ATTR_NAME, &name);
		if (name == NULL)
			continue;

		if (!plan->kernel_upgrade &&
		    strncmp(name, "FreeBSD-kernel", 14) == 0) {
			plan->kernel_upgrade = true;
			strlcpy(plan->kernel_pkg, name,
			    sizeof(plan->kernel_pkg));
		}

		if (plan->n_upgraded < AU_MAX_UPGRADED) {
			strlcpy(plan->upgraded_names[plan->n_upgraded],
			    name, AU_MAX_NAME);
			plan->n_upgraded++;
		}
	}
}

/*
 * apply_blocklist - filter packages matching cfg->blocklist from the job.
 *
 * Compiles each comma-separated POSIX ERE pattern in cfg->blocklist and tests
 * every name in plan->upgraded_names.  If any match, the current job is freed,
 * a new job is constructed from the non-blocked names only, and plan is
 * rescanned.  User-locked packages never reach the solved job, so no special
 * handling is needed for them here.
 *
 * Returns 0 on success, 1 if all candidates were blocked (caller should
 * treat as no-op), -1 on error.
 */
static int
apply_blocklist(struct pkg_jobs **jobs_ptr, struct pkgdb *db,
    const struct au_config *cfg, c_charv_t *reponames,
    struct au_upgrade_plan *plan)
{
	regex_t		*regs;
	char		 buf[4096];
	char		*p, *tok;
	char		 keep[AU_MAX_UPGRADED][AU_MAX_NAME];
	struct pkg_jobs	*newjobs;
	int		 nregs, keep_n, i, j;
	bool		 any_blocked;

	if (cfg->blocklist[0] == '\0')
		return (0);

	/* Count comma-separated patterns. */
	strlcpy(buf, cfg->blocklist, sizeof(buf));
	p = buf;
	nregs = 0;
	while ((tok = strsep(&p, ",")) != NULL) {
		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (*tok != '\0')
			nregs++;
	}
	if (nregs == 0)
		return (0);

	regs = calloc((size_t)nregs, sizeof(regex_t));
	if (regs == NULL) {
		pkg_emit_error("autoupgrade: OOM compiling blocklist regexes");
		return (-1);
	}

	/* Compile patterns. */
	strlcpy(buf, cfg->blocklist, sizeof(buf));
	p = buf;
	j = 0;
	while ((tok = strsep(&p, ",")) != NULL) {
		char errbuf[128];
		int  rc;

		while (*tok == ' ' || *tok == '\t')
			tok++;
		if (*tok == '\0')
			continue;
		rc = regcomp(&regs[j], tok, REG_EXTENDED | REG_NOSUB);
		if (rc != 0) {
			regerror(rc, &regs[j], errbuf, sizeof(errbuf));
			pkg_emit_error("autoupgrade: blocklist pattern '%s': %s",
			    tok, errbuf);
			for (int k = 0; k < j; k++)
				regfree(&regs[k]);
			free(regs);
			return (-1);
		}
		j++;
	}
	nregs = j;

	/* Partition plan into kept and blocked. */
	keep_n      = 0;
	any_blocked = false;
	for (i = 0; i < plan->n_upgraded; i++) {
		bool blocked = false;

		for (j = 0; j < nregs; j++) {
			if (regexec(&regs[j], plan->upgraded_names[i],
			    0, NULL, 0) == 0) {
				blocked = true;
				break;
			}
		}
		if (blocked) {
			pkg_emit_notice("autoupgrade: skipping %s "
			    "(matches blocklist)", plan->upgraded_names[i]);
			any_blocked = true;
			if (plan->n_blocked < AU_MAX_UPGRADED) {
				strlcpy(plan->blocked_names[plan->n_blocked],
				    plan->upgraded_names[i], AU_MAX_NAME);
				plan->n_blocked++;
			}
		} else {
			strlcpy(keep[keep_n], plan->upgraded_names[i],
			    AU_MAX_NAME);
			keep_n++;
		}
	}

	for (j = 0; j < nregs; j++)
		regfree(&regs[j]);
	free(regs);

	if (!any_blocked)
		return (0);

	if (keep_n == 0) {
		pkg_emit_notice("autoupgrade: all candidates blocked; "
		    "nothing to do");
		return (1);
	}

	/* Rebuild the job with only the non-blocked packages. */
	pkg_jobs_free(*jobs_ptr);
	*jobs_ptr = NULL;

	if (pkg_jobs_new(&newjobs, PKG_JOBS_UPGRADE, db) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_new failed "
		    "(blocklist rebuild)");
		return (-1);
	}

	if (pkg_jobs_set_repositories(newjobs, reponames) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_set_repositories failed "
		    "(blocklist rebuild)");
		pkg_jobs_free(newjobs);
		return (-1);
	}

	pkg_jobs_set_flags(newjobs, PKG_FLAG_PKG_VERSION_TEST);

	for (i = 0; i < keep_n; i++) {
		char *name = keep[i];

		if (pkg_jobs_add(newjobs, MATCH_EXACT, &name, 1) == EPKG_FATAL) {
			pkg_emit_error("autoupgrade: pkg_jobs_add(%s) failed "
			    "(blocklist rebuild)", name);
			pkg_jobs_free(newjobs);
			return (-1);
		}
	}

	if (pkg_jobs_solve(newjobs) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_solve failed "
		    "(blocklist rebuild)");
		pkg_jobs_free(newjobs);
		return (-1);
	}

	if (pkg_jobs_count(newjobs) == 0) {
		pkg_jobs_free(newjobs);
		return (1);
	}

	/* Rescan the rebuilt plan (preserve n_blocked / blocked_names). */
	plan->kernel_upgrade = false;
	plan->kernel_pkg[0]  = '\0';
	plan->n_upgraded     = 0;
	scan_plan(newjobs, plan);

	*jobs_ptr = newjobs;
	return (0);
}

/*
 * run_autoremove - remove orphaned packages after an upgrade.
 */
static int
run_autoremove(struct pkgdb *db)
{
	struct pkg_jobs	*jobs = NULL;
	int		 ret = 0;

	if (pkg_jobs_new(&jobs, PKG_JOBS_AUTOREMOVE, db) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_new(autoremove) failed");
		return (-1);
	}

	if (pkg_jobs_solve(jobs) != EPKG_OK) {
		pkg_emit_error("autoupgrade: autoremove solve failed");
		ret = -1;
		goto out;
	}

	if (pkg_jobs_count(jobs) == 0) {
		pkg_emit_notice("autoupgrade: autoremove: nothing to remove");
		goto out;
	}

	pkg_emit_notice("autoupgrade: autoremove: removing %d orphan(s)",
	    pkg_jobs_count(jobs));

	if (pkg_jobs_apply(jobs) != EPKG_OK) {
		pkg_emit_error("autoupgrade: autoremove apply failed");
		ret = -1;
	}

out:
	pkg_jobs_free(jobs);
	return (ret);
}

int
upgrade_run(struct pkgdb *db, const struct au_config *cfg,
    struct au_upgrade_plan *plan)
{
	struct pkg_jobs	*jobs = NULL;
	c_charv_t	 reponames = vec_init();
	char		**vuln_names = NULL;
	int		 n_vuln = 0;
	int		 ret = -1;
	int		 n_repos, n_actions;

	memset(plan, 0, sizeof(*plan));

	n_repos = build_repo_list(cfg, &reponames);
	if (n_repos == 0) {
		pkg_emit_notice("autoupgrade: no repos to upgrade "
		    "(all excluded or none enabled)");
		ret = 1;
		goto out;
	}

	/*
	 * Vulnerable-only mode: fetch the audit database and collect the
	 * names of installed packages with known vulnerabilities.  If none
	 * are found there is nothing to do.
	 */
	if (cfg->only_vulnerable) {
		vuln_names = audit_get_vulnerable_names(db, &n_vuln);
		if (vuln_names == NULL || n_vuln == 0) {
			pkg_emit_notice("autoupgrade: no vulnerable packages "
			    "found; skipping upgrade");
			ret = 1;
			goto out;
		}
		pkg_emit_notice("autoupgrade: %d vulnerable package(s) "
		    "to upgrade", n_vuln);
	}

	update_repos(&reponames);

	if (pkg_jobs_new(&jobs, PKG_JOBS_UPGRADE, db) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_new failed");
		goto out;
	}

	if (pkg_jobs_set_repositories(jobs, &reponames) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_set_repositories failed");
		goto out;
	}

	pkg_jobs_set_flags(jobs, PKG_FLAG_PKG_VERSION_TEST);

	/*
	 * Vulnerable-only: add only the affected package names to the job.
	 * Full-upgrade: pkg_jobs_solve() finds everything that can be upgraded.
	 */
	if (cfg->only_vulnerable) {
		for (int i = 0; i < n_vuln; i++) {
			if (pkg_jobs_add(jobs, MATCH_EXACT,
			    &vuln_names[i], 1) == EPKG_FATAL) {
				pkg_emit_error("autoupgrade: pkg_jobs_add(%s) "
				    "failed", vuln_names[i]);
				goto out;
			}
		}
	}

	if (pkg_jobs_solve(jobs) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_solve failed");
		goto out;
	}

	n_actions = pkg_jobs_count(jobs);
	if (n_actions == 0) {
		pkg_emit_notice("autoupgrade: nothing to upgrade");
		ret = 1;
		goto out;
	}

	pkg_emit_notice("autoupgrade: %d package(s) to upgrade", n_actions);

	scan_plan(jobs, plan);

	/*
	 * Filter packages that match a blocklist pattern.  The job may be
	 * rebuilt with a reduced package set; a return of 1 means everything
	 * was blocked.
	 */
	if (cfg->blocklist[0] != '\0') {
		int bl = apply_blocklist(&jobs, db, cfg, &reponames, plan);
		if (bl == 1) {
			ret = 1;
			goto out;
		}
		if (bl != 0)
			goto out;
	}

	if (be_prepare_safety_net(cfg, plan->kernel_upgrade) != 0) {
		pkg_emit_error("autoupgrade: safety net failed; aborting");
		goto out;
	}

	if (pkg_jobs_apply(jobs) != EPKG_OK) {
		pkg_emit_error("autoupgrade: pkg_jobs_apply failed");
		goto out;
	}

	if (cfg->autoremove)
		run_autoremove(db);

	ret = 0;

out:
	if (jobs != NULL)
		pkg_jobs_free(jobs);
	vec_free(&reponames);
	if (vuln_names != NULL) {
		for (int i = 0; i < n_vuln; i++)
			free(vuln_names[i]);
		free(vuln_names);
	}
	return (ret);
}
