/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */

/*
 * audit.c - vulnerability check via libpkg's audit API.
 *
 * Fetches/refreshes vuln.xml from VULNXML_SITE (default:
 * https://vuxml.freebsd.org/freebsd/vuln.xml.xz) into PKG_DBDIR, then
 * iterates all installed packages and returns the names of those with known
 * vulnerabilities.  Used by upgrade.c when AU_ONLY_UPGRADE_VULNERABLE_PKG
 * is true to restrict the upgrade job to vulnerable packages only.
 */

#include <stdlib.h>
#include <string.h>

#include <pkg.h>
#include <pkg/audit.h>

#include "pkg-autoupgrade.h"
#include "audit.h"

char **
audit_get_vulnerable_names(struct pkgdb *db, int *out_count)
{
	struct pkg_audit		*audit;
	struct pkg_audit_issues		*issues;
	struct pkgdb_it			*it;
	struct pkg			*pkg;
	const char			*name;
	char				**names;
	int				 n, cap;
	int				 fetch_ret;

	*out_count = 0;

	audit = pkg_audit_new();
	if (audit == NULL) {
		pkg_emit_error("autoupgrade: pkg_audit_new failed");
		return (NULL);
	}

	/* Refresh vuln.xml; EPKG_UPTODATE is not an error. */
	fetch_ret = pkg_audit_fetch(NULL, NULL);
	if (fetch_ret != EPKG_OK && fetch_ret != EPKG_UPTODATE) {
		pkg_emit_error("autoupgrade: failed to fetch vuln.xml");
		pkg_audit_free(audit);
		return (NULL);
	}

	if (pkg_audit_load(audit, NULL) != EPKG_OK) {
		pkg_emit_error("autoupgrade: failed to load vuln.xml; "
		    "try running 'pkg audit -F' manually");
		pkg_audit_free(audit);
		return (NULL);
	}

	if (pkg_audit_process(audit) != EPKG_OK) {
		pkg_emit_error("autoupgrade: failed to process vuln.xml");
		pkg_audit_free(audit);
		return (NULL);
	}

	/* Iterate all installed packages, collect vulnerable names. */
	it = pkgdb_query(db, NULL, MATCH_ALL);
	if (it == NULL) {
		pkg_emit_error("autoupgrade: pkgdb_query failed");
		pkg_audit_free(audit);
		return (NULL);
	}

	cap = 64;
	n   = 0;
	names = malloc((size_t)cap * sizeof(*names));
	if (names == NULL) {
		pkg_emit_error("autoupgrade: OOM in audit_get_vulnerable_names");
		pkgdb_it_free(it);
		pkg_audit_free(audit);
		return (NULL);
	}

	pkg = NULL;
	while (pkgdb_it_next(it, &pkg,
	    PKG_LOAD_BASIC | PKG_LOAD_RDEPS) == EPKG_OK) {
		issues = NULL;
		if (!pkg_audit_is_vulnerable(audit, pkg, &issues, false)) {
			pkg_free(pkg);
			pkg = NULL;
			continue;
		}
		pkg_audit_issues_free(issues);

		name = NULL;
		pkg_get(pkg, PKG_ATTR_NAME, &name);
		if (name == NULL) {
			pkg_free(pkg);
			pkg = NULL;
			continue;
		}

		if (n >= cap) {
			char	**tmp;
			int	  newcap = cap * 2;

			tmp = realloc(names, (size_t)newcap * sizeof(*names));
			if (tmp == NULL) {
				pkg_emit_error("autoupgrade: OOM growing "
				    "vulnerable names list");
				break;
			}
			names = tmp;
			cap = newcap;
		}

		names[n] = strdup(name);
		if (names[n] != NULL)
			n++;

		pkg_free(pkg);
		pkg = NULL;
	}

	pkgdb_it_free(it);
	pkg_audit_free(audit);

	if (n == 0) {
		free(names);
		return (NULL);
	}

	*out_count = n;
	return (names);
}
