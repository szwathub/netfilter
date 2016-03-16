#include "inc/rule.h"
#include "inc/color.h"

MODULE_LICENSE("GPL");

extern struct list_head rule_local_in;
extern struct list_head rule_local_out;
extern struct list_head rule_forward;

LIST_HEAD(rule_local_in);
LIST_HEAD(rule_forward);
LIST_HEAD(rule_local_out);

void listfree(struct list_head *p) {
    while(!list_empty(p)) {
        struct rule *entry = list_first_entry(p, struct rule, list);
        list_del(&entry->list);
        kfree(entry);
    }
}

bool init_rule_list(void) {
    INIT_LIST_HEAD(&rule_local_in);
    INIT_LIST_HEAD(&rule_forward);
    INIT_LIST_HEAD(&rule_local_out);

    return true;
}

void destroy_rule_list(void) {
    listfree(&rule_local_in);
    listfree(&rule_forward);
    listfree(&rule_local_out);
}
