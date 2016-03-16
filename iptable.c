#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>

#include "inc/color.h"
#include "inc/status.h"

const char *file_dev = "/dev/chardev";
const char *file_rule = "iptables";

enum {SRC = 90, DST};
enum TARGET {DROP = 0, ACCEPT};
enum CHAIN {INPUT = 120, FORWARD, OUTPUT};

int strtoi(char* str);
void file_save();

static char *prog_name = "iptable";
static char *prog_vers = "1.0.0";

char* const short_options = "A:I:D:C:Ss:d:p:j:VF:Lht:l:";

static const struct option options[] = {
    {.name = "append",      .has_arg = 1, .val = 'A'},
    {.name = "insert",      .has_arg = 1, .val = 'I'},
    {.name = "delete",      .has_arg = 1, .val = 'D'},
    {.name = "check",       .has_arg = 1, .val = 'C'},
    {.name = "list",        .has_arg = 0, .val = 'L'},
    {.name = "save",        .has_arg = 0, .val = 'S'},
    {.name = "source",      .has_arg = 1, .val = 's'},
    {.name = "destination", .has_arg = 1, .val = 'd'},
    {.name = "src",         .has_arg = 1, .val = 's'},
    {.name = "dst",         .has_arg = 1, .val = 'd'},
    {.name = "protocol",    .has_arg = 1, .val = 'p'},
    {.name = "sport",       .has_arg = 1, .val = '1'},
    {.name = "dport",       .has_arg = 1, .val = '2'},
    {.name = "jump",        .has_arg = 1, .val = 'j'},
    {.name = "help",        .has_arg = 0, .val = 'h'},
    {.name = "version",     .has_arg = 0, .val = 'V'},
    {.name = "fulsh",       .has_arg = 1, .val = 'F'},
    {.name = "time",        .has_arg = 1, .val = 't'},
    {.name = "line-number", .has_arg = 1, .val = 'l'}
};
static void printhelp() {
    printf("%s v%s\n\n"
"Usge: %s -[AD] rule-specification [options]\n"
"      %s -I chain [rulenum] rule-specification [options]\n"
"      %s -L \n"
"      %s -C [chain]\n"
"      %s -S (save chain to file)\n"
"      %s -h (print this help information)\n\n",
        prog_name, prog_vers, prog_name, prog_name,
        prog_name, prog_name, prog_name, prog_name);

    printf(
"Commands:\n"
"Either long or short optins are allowed.\n"
"  --append -A chain        Append to chain\n"
"  --check  -C chain        Check for existence of a rule\n"
"  --delete -D chain        Delete matching rule from chain\n"
"  --delete -D chain rulenum\n"
"              Delete rule rulenum (1 = first) from chain\n"
"  --insert -I chain [rulenum]\n"
"              Insert in chain as rulenum (default 1 = first)\n"
"  --save   -S chain        Save chain to a file\n"
"  --list   -L              List the rule in all chain\n"
"  --fulsh  -F [chain[ALL]]      Delete all rules in chain or all chains\n\n"

"options:\n"
"  --protocol       -p      prot protocol: by number or name, eg. 'tcp'\n"
"  --source         -s      address[/mask][...]\n"
"                           source specification\n"
"  --destination    -d      address[/mask][...]\n"
"                           destination specification\n"
"  --sport                  source port\n"
"  --dport                  destination port\n"
"  --jump           -j      target\n"
"                           target for rule (may load target externsion)\n"
"  --time           -t      set time, eg. 'hh:mm:ss--hh:mm:ss'\n"
"  --version        -V      print package version.\n");
}

int main(int argc, char const *argv[]) {
    int fd;
    int c;
    int cmd;
    struct user_rule *rule_node = (struct user_rule*)malloc(sizeof(struct user_rule));
    fd = open("/dev/chardev", O_RDWR);

    while((c = getopt_long(argc, (char * const*)argv,
            short_options, options, NULL)) != -1) {
        switch(c) {
            case 'A' :
                cmd = c;
                if(strcmp("INPUT", optarg) == 0) {
                    rule_node->chain = INPUT;
                }
                else if(strcmp("OUTPUT", optarg) == 0) {
                    rule_node->chain = OUTPUT;
                }
                else {
                    rule_node->chain = FORWARD;
                }
                break;
            case 'D' :
                cmd = c;
                if(strcmp("INPUT", optarg) == 0) {
                    rule_node->chain = INPUT;
                }
                else if(strcmp("OUTPUT", optarg) == 0) {
                    rule_node->chain = OUTPUT;
                }
                else {
                    rule_node->chain = FORWARD;
                }
                break;
            case 'I' :
                cmd = c;
                if(strcmp("INPUT", optarg) == 0) {
                    rule_node->chain = INPUT;
                }
                else if(strcmp("OUTPUT", optarg) == 0) {
                    rule_node->chain = OUTPUT;
                }
                else {
                    rule_node->chain = FORWARD;
                }
                break;
            case 'C' :
                printf("Check\n");
                break;
            case 'L' :
                ioctl(fd, RULE_LIST);
                break;
            case 'F' :
                if(strcmp("INPUT", optarg) == 0) {
                    rule_node->chain = INPUT;
                }
                else if(strcmp("OUTPUT", optarg) == 0) {
                    rule_node->chain = OUTPUT;
                }
                else if(strcmp("FORWARD", optarg) == 0) {
                    rule_node->chain = FORWARD;
                }
                else {
                    rule_node->chain = FORWARD + 1;
                }
                ioctl(fd, RULE_FULSH, rule_node);
                break;
            case 'S' :
                ioctl(fd, RULE_SAVE);
                file_save();
                break;
            case 's' :
                //printf("source ip: optarg: %s\n", optarg);
                strcpy(rule_node->saddr, optarg);
                break;
            case 'd' :
                strcpy(rule_node->daddr, optarg);
                break;
            case 'p' :
                strcpy(rule_node->prot, optarg);
                break;
            case 'j' :
                if(strcmp("ACCEPT", optarg) == 0) {
                    rule_node->target = ACCEPT;
                }
                else {
                    rule_node->target = DROP;
                }
                break;
            case 't' :
                strcpy(rule_node->_time, optarg);
                break;
            case 'h' :
                printhelp();
                break;
            case 'V' :
                printf("%s v%s\n", prog_name, prog_vers);
                break;
            case '1' :
                strcpy(rule_node->sport, optarg);
                //printf("source port %s\n", rule_node->src.port);
                break;
            case '2' :
                strcpy(rule_node->dport, optarg);
                //printf("source port %s\n", rule_node->dst.port);
                break;
            case 'l':
                rule_node->line = strtoi(optarg);
                break;
            default:
                break;
        }
    }
    switch(cmd) {
        case 'I':
            ioctl(fd, RULE_INSERT, rule_node);
            break;
        case 'A':
            ioctl(fd, RULE_APPEND, rule_node);
            break;
        case 'D':
            ioctl(fd, RULE_DELETE, rule_node);
            break;
    }
    close(fd);
    return 0;
}


int strtoi(char* str) {
    int ret = 0;
    while(*str && *str != ' ' && *str != '\n') {
        if(*str >= '0' && *str <= '9') {
            ret = ret * 10 + (*str - '0');
        }
        str++;
    }

    return ret;
}

void file_save() {
    FILE *fp0 = NULL;
    FILE *fp1 = NULL;
    char buf[100];

    fp0 = fopen(file_dev, "r");
    fp1 = fopen(file_rule, "w+");

    fseek(fp0, 0, SEEK_SET);
    while(!feof(fp0)) {
        fgets(buf, 100, fp0);
        printf("%s\n", fp0);
        fprintf(fp1, "%s", buf);
    }
    fclose(fp0);
    fclose(fp1);
}
