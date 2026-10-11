/*-
 * SPDX-License-Identifier: BSD-2-Clause
 * SPDX-FileCopyrightText: 2026 Cybermancer Infosec B.V.
 */
#ifndef AU_CONFIG_H
#define	AU_CONFIG_H

struct pkg_plugin;
struct au_config;

int	config_register_keys(struct pkg_plugin *);
int	config_load(struct pkg_plugin *, struct au_config *);

#endif /* AU_CONFIG_H */
