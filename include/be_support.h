/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
#ifndef AU_BE_SUPPORT_H
#define	AU_BE_SUPPORT_H

#include <stdbool.h>

struct au_config;

/* Returns true if / is on a ZFS dataset. */
bool	be_is_zfs_root(void);

/*
 * Create a boot environment named "<prefix>-YYYYMMDDTHHMMSS" using libbe,
 * then prune BEs with the same prefix to at most keep entries (oldest first).
 * Returns 0 on success, -1 on error (non-fatal; caller logs and continues).
 */
int	be_create_snapshot(const struct au_config *cfg);

/*
 * Rename /boot/kernel to /boot/kernel.old as a pre-upgrade safety net on
 * UFS roots.  The previous .old is removed first.  Returns 0 on success.
 */
int	ufs_backup_kernel(void);

/*
 * Dispatch: ZFS root -> be_create_snapshot(); UFS root with kernel_upgrade
 * and ufs_kernel_backup enabled -> ufs_backup_kernel().
 * Returns 0 on success, -1 on error.
 */
int	be_prepare_safety_net(const struct au_config *cfg, bool kernel_upgrade);

#endif /* AU_BE_SUPPORT_H */
