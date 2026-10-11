/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */

#ifndef AU_AUDIT_H
#define	AU_AUDIT_H

#include <pkg.h>
#include <pkg/audit.h>

/*
 * audit_get_vulnerable_names - fetch/refresh vuln.xml and return the names
 * of all installed packages that have known vulnerabilities.
 *
 * On success returns a heap-allocated array of heap-allocated strings;
 * *out_count is set to the number of entries.  The caller must free each
 * string and then the array itself.
 *
 * Returns NULL with *out_count == 0 if nothing is vulnerable or on error
 * (errors are emitted via pkg_emit_error).
 */
char	**audit_get_vulnerable_names(struct pkgdb *db, int *out_count);

#endif /* AU_AUDIT_H */
