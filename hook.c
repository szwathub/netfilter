#include "inc/color.h"
#include "inc/hook.h"
#include "inc/rule.h"

// #include "usr/include/stdio.h"

MODULE_LICENSE("GPL");
extern struct list_head rule_local_in;
extern struct list_head rule_local_out;
extern struct list_head rule_forward;
extern struct mem_dev *mem_devp;
extern struct mem_dev *mem_log;

__u8 GetProtocol(struct sk_buff *skb) {
    struct sk_buff *tmp_skb;
    struct iphdr *ip;
    tmp_skb = skb_copy(skb, 1);
    ip = ip_hdr(tmp_skb);

    return ip->protocol;
}

uint32_t GetAddr(struct sk_buff *skb, int flag){
    struct sk_buff *sk;
    struct iphdr *ip;
    sk = skb_copy(skb, 1);
    ip = ip_hdr(sk);
    if(flag == SRC) {
        return ip->saddr;
    }
    else if(flag == DST) {
        return ip->daddr;
    }
    else
        return 0;
}

uint16_t GetPort(struct sk_buff *skb, int flag){
    struct sk_buff *sk;
    struct tcphdr *tcph;
    struct udphdr *udph;
    uint16_t port = 0;
    sk = skb_copy(skb, 1);
    tcph = tcp_hdr(sk);
    udph = udp_hdr(sk);

    switch(GetProtocol(sk)){
        case IPPROTO_TCP:
            if(flag == SRC) {
                port = ntohs(tcph->source);
            }
            else if(flag == DST) {
                port = ntohs(tcph->dest);
            }
            break;
        case IPPROTO_UDP:
            if(flag == SRC) {
                port = ntohs(udph->source);
            }
            else if(flag == DST) {
                port = ntohs(udph->dest);
            }
            break;
    }
    return port;
}

bool CompareTime(struct rule_time rule_tm, ktime_t package_time){
    struct rtc_time tm;
    int hour, min, sec;
    int allsec, brulesec, erulesec;
    //int year, month, mday;
    rtc_time_to_tm(package_time.tv64/1000000000 + (8 * 60 * 60), &tm);
    //year = tm.tm_year + 1900;
    //month = tm.tm_mon + 1;
    //mday = tm.tm_mday;
    hour = tm.tm_hour;
    min = tm.tm_min;
    sec = tm.tm_sec;

    allsec = hour * 3600 + min * 60 + sec;
    brulesec = rule_tm.btime.tm_hour * 3600 + rule_tm.btime.tm_min * 60 + rule_tm.btime.tm_sec;
    erulesec = rule_tm.etime.tm_hour * 3600 + rule_tm.etime.tm_min * 60 + rule_tm.etime.tm_sec;
    //printk("time@ (%04d-%02d-%02d %02d:%02d:%02d)\n",year, month, mday, hour, min, sec);
    //printk("%d", allsec);

    if(rule_tm.valid == true || (allsec >= brulesec && allsec <= erulesec)) {
        return true;
    }
    return false;
}

bool CompareID_with_mask(uint32_t addr1, uint32_t addr2, uint8_t mask){
	uint32_t addr1_temp, addr2_temp;
	addr1_temp = MASK_IP(addr1, mask);
	addr2_temp = MASK_IP(addr2, mask);
	return (addr1_temp == addr2_temp);
}

bool filter(struct sk_buff *skb, struct list_head *list_in){
    struct sk_buff *sk;
    struct rule *ptr;
    uint32_t s_addr, d_addr;
    __u8 prot;
    uint16_t s_port, d_port;
    ktime_t tm;

    if(!skb) {
        return false;
    }

    sk = skb_copy(skb,1);
    prot = GetProtocol(sk);
    s_addr = GetAddr(sk, SRC);
    d_addr = GetAddr(sk, DST);
    s_port = GetPort(sk, SRC);
    d_port = GetPort(sk, DST);
    tm = sk->tstamp;

    struct rtc_time sys_tm;
	struct timeval timeval;
	unsigned long local_time;

    do_gettimeofday(&timeval);
    local_time = (u32)(timeval.tv_sec + (8 * 60 * 60));
    rtc_time_to_tm(local_time, &sys_tm);

    if(!list_empty(list_in)) {
        list_for_each_entry(ptr, list_in, list) {
            if((ptr->sport == s_port || ptr->anysport == true)
                && (ptr->dport == d_port || ptr->anydport == true)
                && (ptr->tm.valid == 0 || CompareTime(ptr->tm, tm))
                && (ptr->prot == prot || ptr->anyprot == true)
                && (CompareID_with_mask(ptr->src.addr, s_addr, ptr->src.mask) || ptr->src.anyaddr == true)
                && (CompareID_with_mask(ptr->dst.addr, s_addr, ptr->dst.mask) || ptr->dst.anyaddr == true)) {

                    printk("@time[%04d-%02d-%02d %02d:%02d:%02d] %pI4 to %pI4 %s\n",
                            sys_tm.tm_year + 1900, sys_tm.tm_mon + 1,
                            sys_tm.tm_mday, sys_tm.tm_hour, sys_tm.tm_min, sys_tm.tm_sec,
                            &ptr->src.addr, &ptr->dst.addr,
                            ptr->target?"ACCEPT":"DROP");
                    return ptr->target;
                }
            }
    }
    return NF_ACCEPT;
}

unsigned int local_in_func(unsigned int hooknum,
                struct sk_buff *skb,
                const struct net_device *in,
                const struct net_device *out,
                int (*okfn)(struct sk_buff *)) {
    struct sk_buff *sk;
    sk = skb_copy(skb, 1);

    return filter(sk, &rule_local_in);
}

unsigned int forward_func(unsigned int hooknum,
                struct sk_buff *skb,
                const struct net_device *in,
                const struct net_device *out,
                int (*okfn)(struct sk_buff *)) {
    struct sk_buff *sk;
    sk = skb_copy(skb, 1);

    return filter(sk, &rule_forward);
}

unsigned int local_out_func(unsigned int hooknum,
                struct sk_buff *skb,
                const struct net_device *in,
                const struct net_device *out,
                int (*okfn)(struct sk_buff *)) {
    struct sk_buff *sk;
    sk = skb_copy(skb, 1);

    return filter(sk, &rule_local_out);
}
