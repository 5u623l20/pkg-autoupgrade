/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */

#ifndef AU_MAIL_H
#define	AU_MAIL_H

#include <stdbool.h>
#include "pkg-autoupgrade.h"

/*
 * mail_send - conditionally send a post-upgrade report via sendmail(8).
 *
 * Does nothing when cfg->mail_to is empty.  Whether a message is sent
 * depends on cfg->mail_report:
 *   "always"    - always send
 *   "on-error"  - only when had_error is true
 *   "on-change" - when at least one package was upgraded or had_error
 */
void	mail_send(const struct au_config *cfg,
	    const struct au_upgrade_plan *plan,
	    const char * const *notices, int n_notices,
	    bool had_error);

#endif /* AU_MAIL_H */
