#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>


#include "inc/hook.h"
#include "inc/color.h"
#include "inc/rule.h"
#include "inc/chardev.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZhiweiSun");

//static struct nf_hook_ops NFHO_PRE_ROUTING;
static struct nf_hook_ops NFHO_LOCAL_IN;
static struct nf_hook_ops NFHO_LOCAL_OUT;
static struct nf_hook_ops NFHO_FORWARD;
//static struct nf_hook_ops NFHO_POST_ROUTING;

static int kexec_test_init(void) {
    printk(LIGHT_GREEN"kexec test start... \n"NONE);
    NFHO_LOCAL_IN.hook = local_in_func;
    //NFHO_LOCAL_IN.owner = NULL;
    NFHO_LOCAL_IN.pf = PF_INET;
    NFHO_LOCAL_IN.hooknum = NF_INET_LOCAL_IN;
    NFHO_LOCAL_IN.priority = NF_IP_PRI_FIRST;

    NFHO_FORWARD.hook = forward_func;
    //NFHO_FORWARD.owner = NULL;
    NFHO_FORWARD.pf = PF_INET;
    NFHO_FORWARD.hooknum = NF_INET_FORWARD;
    NFHO_FORWARD.priority = NF_IP_PRI_FIRST;

    NFHO_LOCAL_OUT.hook = local_out_func;
    //NFHO_LOCAL_OUT.owner = NULL;
    NFHO_LOCAL_OUT.pf = PF_INET;
    NFHO_LOCAL_OUT.hooknum = NF_INET_LOCAL_OUT;
    NFHO_LOCAL_OUT.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&NFHO_LOCAL_IN);// 注册一个钩子函数
    nf_register_hook(&NFHO_FORWARD);
    nf_register_hook(&NFHO_LOCAL_OUT);

    init_rule_list();
    dev_init();
    return 0;
}

static void kexec_test_exit(void) {
    printk(LIGHT_GREEN"kexec test exit ...\n"NONE);

    nf_unregister_hook(&NFHO_LOCAL_IN);
    nf_unregister_hook(&NFHO_FORWARD);
    nf_unregister_hook(&NFHO_LOCAL_OUT);

    destroy_rule_list();
    dev_exit();
}


module_init(kexec_test_init);
module_exit(kexec_test_exit);
