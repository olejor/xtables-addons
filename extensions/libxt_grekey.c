/*
 *      "grekey" target extension for iptables
 *      Copyright Ole Jorgensen <ole [at] jorgensen.no>, 2013
 *      Copyright Jorgen Hovland <j [at] hovland.cx>, 2013
 *      Sponsered by Bouvet ASA <http://bouvet.no>
 *
 *      xt_GREKEY overwrites the key field of a GRE packet if present.
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License version 2 as
 *      published by the Free Software Foundation.
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include "compat_user.h"

static void grekey_tg_help(void) {
        // in the future add options to set key present bit to 1/0
        // and/or key to given value
	printf("grekey takes no options\n");
}

static int grekey_tg_parse(
    int c,
    char **argv,
    int invert,
    unsigned int *flags,
    const void *entry,
    struct xt_entry_target **target
) {
	return 0;
}

static void grekey_tg_check(unsigned int flags) {
}

static struct xtables_target grekey_tg_reg = {
	.version       = XTABLES_VERSION,
	.name          = "grekey",
	.revision      = 0,
	.family        = NFPROTO_IPV4,
	.help          = grekey_tg_help,
	.parse         = grekey_tg_parse,
	.final_check   = grekey_tg_check,
};

static __attribute__((constructor)) void grekey_tg_ldr(void) {
	xtables_register_target(&grekey_tg_reg);
}
