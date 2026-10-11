/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
/*
 * mail.c - post-upgrade email notification via sendmail(8).
 *
 * Opens a pipe to /usr/sbin/sendmail -t and writes a plain-text message
 * whose To: header carries the recipient.  This works with any MTA that
 * provides the standard sendmail compatibility interface.
 *
 * The caller decides whether to send at all; mail_send() applies the
 * AU_MAIL_REPORT filter (always / on-error / on-change) internally so
 * the caller does not need to duplicate that logic.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <pkg.h>

#include "pkg-autoupgrade.h"
#include "mail.h"

void
mail_send(const struct au_config *cfg,
    const struct au_upgrade_plan *plan,
    const char * const *notices, int n_notices,
    bool had_error)
{
	FILE	*fp;
	char	 hostname[256];
	bool	 send;

	if (cfg->mail_to[0] == '\0')
		return;

	if (strcmp(cfg->mail_report, "always") == 0) {
		send = true;
	} else if (strcmp(cfg->mail_report, "on-error") == 0) {
		send = had_error;
	} else {
		/* on-change: send if anything was upgraded or an error occurred */
		send = (plan->n_upgraded > 0 || had_error);
	}

	if (!send)
		return;

	hostname[0] = '\0';
	(void)gethostname(hostname, sizeof(hostname) - 1);

	fp = popen("/usr/sbin/sendmail -t", "w");
	if (fp == NULL) {
		pkg_emit_error("autoupgrade: cannot open pipe to sendmail");
		return;
	}

	/* RFC 5322 headers - To: is read by sendmail -t */
	fprintf(fp, "To: %s\r\n", cfg->mail_to);
	fprintf(fp, "From: root@%s\r\n", hostname);
	fprintf(fp, "Subject: [pkg-autoupgrade] %s on %s\r\n",
	    had_error          ? "upgrade FAILED" :
	    plan->n_upgraded > 0 ? "upgrade complete" : "no changes",
	    hostname);
	fprintf(fp, "MIME-Version: 1.0\r\n");
	fprintf(fp, "Content-Type: text/plain; charset=UTF-8\r\n");
	fprintf(fp, "\r\n");

	/* Body */
	fprintf(fp, "pkg-autoupgrade report from %s\n\n", hostname);

	if (had_error)
		fprintf(fp, "STATUS: FAILED\n\n");
	else if (plan->n_upgraded > 0)
		fprintf(fp, "STATUS: success (%d package(s) upgraded)\n\n",
		    plan->n_upgraded);
	else
		fprintf(fp, "STATUS: nothing to do\n\n");

	if (plan->n_upgraded > 0) {
		fprintf(fp, "Upgraded (%d):\n", plan->n_upgraded);
		for (int i = 0; i < plan->n_upgraded; i++)
			fprintf(fp, "  %s\n", plan->upgraded_names[i]);
		fprintf(fp, "\n");
	}

	if (plan->n_blocked > 0) {
		fprintf(fp, "Skipped by blocklist (%d):\n", plan->n_blocked);
		for (int i = 0; i < plan->n_blocked; i++)
			fprintf(fp, "  %s\n", plan->blocked_names[i]);
		fprintf(fp, "\n");
	}

	if (n_notices > 0) {
		fprintf(fp, "Pending notices (%d):\n", n_notices);
		for (int i = 0; i < n_notices; i++)
			fprintf(fp, "  %s\n", notices[i]);
		fprintf(fp, "\n");
	}

	if (pclose(fp) != 0)
		pkg_emit_error("autoupgrade: sendmail exited with error");
}
