/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
/*
 * motd.c - manage the pkg-autoupgrade section in /var/run/motd.
 *
 * /var/run/motd is regenerated at boot by the motd(8) rc script from
 * /etc/motd.template, which means any additions we make are wiped on the
 * next reboot.  To survive reboots, we persist pending notices to
 * AU_STATE_NOTICES and provide a separate rc.d script
 * (pkg-autoupgrade-motd, REQUIRE: motd) that runs motd_repopulate() to
 * re-stamp /var/run/motd after the system motd script has run.
 *
 * The section in /var/run/motd looks like:
 *
 *   # --- pkg-autoupgrade begin ---
 *   Service needs restart after upgrade: nginx (not in AU_RESTART_SERVICES)
 *   System reboot required: kernel was upgraded (FreeBSD-kernel-generic)
 *   # --- pkg-autoupgrade end ---
 *
 * We rewrite the entire section atomically: write to a temp file alongside
 * /var/run/motd, then rename into place.
 */

#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pkg.h>

#include "pkg-autoupgrade.h"
#include "motd.h"

#define	MOTD_TMP	AU_MOTD_PATH ".au.tmp"
#define	LINE_MAX_LEN	1024

/*
 * write_section - append our begin/notices/end block to fp.
 */
static void
write_section(FILE *fp, char **notices, int n_notices)
{
	fprintf(fp, "%s\n", AU_MOTD_BEGIN);
	for (int i = 0; i < n_notices; i++) {
		if (notices[i] != NULL)
			fprintf(fp, "%s\n", notices[i]);
	}
	fprintf(fp, "%s\n", AU_MOTD_END);
}

/*
 * motd_rewrite - rewrite AU_MOTD_PATH, replacing (or removing) our marked
 * section.  Lines between AU_MOTD_BEGIN and AU_MOTD_END (inclusive) are
 * stripped; if n_notices > 0 the new section is appended at the end.
 */
static void
motd_rewrite(char **notices, int n_notices)
{
	FILE	*in, *out;
	char	 line[LINE_MAX_LEN];
	bool	 in_section = false;

	in  = fopen(AU_MOTD_PATH, "r");
	out = fopen(MOTD_TMP, "w");

	if (out == NULL) {
		pkg_emit_error("autoupgrade: cannot open %s for writing: %s",
		    MOTD_TMP, strerror(errno));
		if (in != NULL)
			fclose(in);
		return;
	}

	if (in != NULL) {
		while (fgets(line, sizeof(line), in) != NULL) {
			/* Strip the trailing newline for comparison. */
			size_t len = strlen(line);
			if (len > 0 && line[len - 1] == '\n')
				line[len - 1] = '\0';

			if (strcmp(line, AU_MOTD_BEGIN) == 0) {
				in_section = true;
				continue;
			}
			if (strcmp(line, AU_MOTD_END) == 0) {
				in_section = false;
				continue;
			}
			if (!in_section)
				fprintf(out, "%s\n", line);
		}
		fclose(in);
	}

	if (n_notices > 0)
		write_section(out, notices, n_notices);

	fclose(out);

	if (rename(MOTD_TMP, AU_MOTD_PATH) != 0) {
		pkg_emit_error("autoupgrade: rename(%s, %s) failed: %s",
		    MOTD_TMP, AU_MOTD_PATH, strerror(errno));
		(void)unlink(MOTD_TMP);
	}
}

/*
 * state_save - write notices to the persistent state file, one per line.
 * An empty notices list truncates the file (clears pending state).
 */
static void
state_save(char **notices, int n_notices)
{
	FILE	*fp;
	int	 fd;

	if (mkdir(AU_STATE_DIR, 0755) != 0 && errno != EEXIST) {
		pkg_emit_error("autoupgrade: mkdir(%s) failed: %s",
		    AU_STATE_DIR, strerror(errno));
		return;
	}

	fd = open(AU_STATE_NOTICES,
	    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		pkg_emit_error("autoupgrade: open(%s) failed: %s",
		    AU_STATE_NOTICES, strerror(errno));
		return;
	}

	fp = fdopen(fd, "w");
	if (fp == NULL) {
		close(fd);
		return;
	}

	for (int i = 0; i < n_notices; i++) {
		if (notices[i] != NULL)
			fprintf(fp, "%s\n", notices[i]);
	}
	fclose(fp);
}

/*
 * state_load - read lines from the persistent state file into notices[].
 * Returns the count of notices loaded.  The caller must free each entry.
 */
static int
state_load(char **notices, int max)
{
	FILE	*fp;
	char	 line[512];
	int	 n = 0;

	fp = fopen(AU_STATE_NOTICES, "r");
	if (fp == NULL)
		return (0);

	while (n < max && fgets(line, sizeof(line), fp) != NULL) {
		size_t len = strlen(line);
		if (len > 0 && line[len - 1] == '\n')
			line[len - 1] = '\0';
		if (*line == '\0')
			continue;
		notices[n] = strdup(line);
		if (notices[n] != NULL)
			n++;
	}
	fclose(fp);
	return (n);
}

void
motd_update(char **notices, int n_notices)
{
	motd_rewrite(notices, n_notices);
	state_save(notices, n_notices);
}

void
motd_repopulate(void)
{
	char	*notices[AU_MAX_NOTICES];
	int	 n;

	n = state_load(notices, AU_MAX_NOTICES);
	if (n == 0)
		return;

	motd_rewrite(notices, n);

	for (int i = 0; i < n; i++)
		free(notices[i]);
}
