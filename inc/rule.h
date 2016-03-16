#ifndef __RULE_H__
#define __RULE_H__

#include <linux/time.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/rtc.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/fs.h>
//typedef int BOOL;
//#define TRUE  1
//#define FALSE 0

enum {SRC = 90, DST};
enum TARGET {DROP = 0, ACCEPT};
enum CHAIN {INPUT = 120, FORWARD, OUTPUT};

#define MASK_IP(ip, mask) (ip & (0xffffffff << mask))


struct rule_time {
    struct rtc_time btime;
    struct rtc_time etime;
    bool valid;
};

typedef struct rule {
    struct {
        uint32_t addr;      // IP
        uint8_t mask;
        bool anyaddr;
    }src;
    uint16_t sport;        //source port
    bool anysport;

    struct {
        uint32_t addr;      // IP
        uint8_t mask;
        bool anyaddr;
    }dst;
    uint16_t dport;      //destination port
    bool anydport;

    __u8 prot;
    bool anyprot;

    struct rule_time tm;
    enum TARGET target;
    struct list_head list;
}RULE;

bool init_rule_list(void);
void destroy_rule_list(void);
void listfree(struct list_head *p);

#endif
