/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
#ifndef AU_MOTD_H
#define	AU_MOTD_H

/*
 * motd_update - write (or clear) the pkg-autoupgrade section in
 * /var/run/motd.
 *
 * The section is delimited by AU_MOTD_BEGIN and AU_MOTD_END markers.  If
 * n_notices == 0 the section is removed.  If the file does not exist it is
 * created (it may be absent on a very fresh boot before motd(8) runs).
 *
 * Also writes/clears the persistent state file AU_STATE_NOTICES so that the
 * pkg-autoupgrade-motd rc.d script can repopulate /var/run/motd after reboot.
 */
void	motd_update(char **notices, int n_notices);

/*
 * motd_repopulate - read the persistent state file and re-stamp
 * /var/run/motd.  Called at boot by the rc.d script.
 */
void	motd_repopulate(void);

#endif /* AU_MOTD_H */
