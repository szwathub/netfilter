#ifndef __STATUS_H__
#define __STATUS_H__

#define RULE_LIST       0x0001

#define RULE_FULSH      0x0003
#define RULE_INSERT     0x0004
#define RULE_APPEND     0x0005
#define RULE_DELETE     0x0006
#define RULE_SAVE       0x0007


struct user_rule {
    int chain;
    char saddr[20];
    char sport[6];
    char daddr[20];
    char dport[6];
    char prot[5];
    char _time[20];
    int target;
    int line;
};

#endif
