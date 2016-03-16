#ifndef __HOOK_H__
#define __HOOK_H__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/socket.h>
#include <linux/net.h>

unsigned int local_in_func(unsigned int hooknum,
                struct sk_buff *skb,
                const struct net_device *in,
                const struct net_device *out,
                int (*okfn)(struct sk_buff *));

unsigned int forward_func(unsigned int hooknum,
                struct sk_buff *skb,
                const struct net_device *in,
                const struct net_device *out,
                int (*okfn)(struct sk_buff *));

unsigned int local_out_func(unsigned int hooknum,
                struct sk_buff *skb,
                const struct net_device *in,
                const struct net_device *out,
                int (*okfn)(struct sk_buff *));

static inline unsigned int inet_addr(char *str) {
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int *)arr;
}

#endif
