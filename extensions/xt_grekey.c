/*
 *      "grekey" target extension for iptables
 *      Copyright Ole Jorgensen <ole [at] jorgensen.no>, 2013
 *      Copyright Jorgen Hovland <j [at] hovland.cx>, 2013
 *      Sponsered by Bouvet ASA <http://bouvet.no>
 *
 *	xt_GREKEY overwrites the key field of a GRE packet if present.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2 as
 *	published by the Free Software Foundation.
 */


#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/version.h>
#include <linux/netfilter/x_tables.h>
#include "compat_xtables.h"

static unsigned int
grekey_tg(struct sk_buff **skb, const struct xt_action_param *par) {
    unsigned char *data = NULL;
    unsigned int pos = 20, key = 0, newkey = 123456;

    // Make it writeable so we can change data
    if (!skb_make_writable(skb, (*skb)->len)) {
        return NF_DROP;
   }

    data = (*skb)->data;
    
    if (data[20] & 0x80) {
        pos += 2; // Checksum GRE header is used
    }

    if (data[20] & 0x20) {
            // Key is used
            key += ((unsigned int) data[pos+4]) * 256 * 256 * 256;
            key += ((unsigned int) data[pos+5]) * 256 * 256;
            key += ((unsigned int) data[pos+6]) * 256;
            key += ((unsigned int) data[pos+7]);

            if (key != newkey) {
                    // Rewrite key
                    key = newkey;
                    data[pos+7] = key % 256;
                    key /= 256;
                    data[pos+6] = key % 256;
                    key /= 256;
                    data[pos+5] = key % 256;
                    key /= 256;
                    data[pos+4] = key;
            }
    } else {
            // Key is not used
    }

    return XT_CONTINUE;
}

static struct xt_target grekey_tg_reg __read_mostly = {
    .name     = "grekey",
    .revision = 0,
    .family   = NFPROTO_IPV4,
    .table    = "mangle",
//    .hooks    = (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) | (1 << NF_INET_LOCAL_OUT),
    .proto    = IPPROTO_GRE,
    .target   = grekey_tg,
    .me       = THIS_MODULE,
};

static int __init grekey_tg_init(void) {
    return xt_register_target(&grekey_tg_reg);
}

static void __exit grekey_tg_exit(void) {
	xt_unregister_target(&grekey_tg_reg);
}

module_init(grekey_tg_init);
module_exit(grekey_tg_exit);

MODULE_DESCRIPTION("Xtables: Overwrite GRE key field if set");
MODULE_AUTHOR("Ole Jorgensen <ole@jorgensen.no>");
MODULE_AUTHOR("Jorgen Hovland <j@hovland.cx>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_grekey");
