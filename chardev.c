#include <linux/string.h>

#include "inc/chardev.h"
#include "inc/color.h"
#include "inc/hook.h"
#include "inc/status.h"

MODULE_LICENSE("GPL");

unsigned int major = MEMDEV_MAJOR;
unsigned int minor = MEMDEV_MAIOR;

dev_t devno;
struct cdev iptable_cdev;
struct mem_dev *mem_devp;  //设备结构体指针
struct mem_dev *mem_log;
int mutex = 1;
int counter = 0;


extern struct list_head rule_local_in;
extern struct list_head rule_local_out;
extern struct list_head rule_forward;

struct file_operations rule_fops = {
	.owner = THIS_MODULE,
	.llseek = file_llseek,
    .unlocked_ioctl = file_ioctl,
	.open = file_open,
	.read = file_read,
	.write = file_write,
	.release = file_release,
};
char *addr_inet(uint32_t inet) {
    char *str = NULL;
    uint8_t *arr;
    uint8_t a, b, c, d;

    str = kmalloc(20 * sizeof(char), GFP_KERNEL);
    arr = (uint8_t *)&inet;
    a = arr[0]; b = arr[1]; c = arr[2]; d = arr[3];
    sprintf(str, "%u.%u.%u.%u", a, b, c, d);

    return str;
}
uint16_t strtoi(char* str) {
    uint16_t ret = 0;
    while(*str && *str != ' ' && *str != '\n') {
        if(*str >= '0' && *str <= '9') {
            ret = ret * 10 + (*str - '0');
        }
        str++;
    }

    return ret;
}

char *reverse(char *str) {
    char tmp;
    char *head = str;
    char *tail = str + strlen(str) - 1;

    while(tail > head) {
        tmp = *head;
        *head++ = *tail;
        *tail-- = tmp;
    }

    return str;
}

char* itostr(int num) {
    char out[100];
    int i = 0;

    do {
        out[i++] = num % 10 + '0';
        num /= 10;
    } while(num > 0);
    out[i] = '\0';
    return reverse(out);
}

void print_list(struct list_head *list_in) {
    struct rule *tmp;
    char sinput[100];
    char dinput[100];

    if(!list_empty(list_in)) {
        list_for_each_entry(tmp, list_in, list) {
            printk("%-6s", tmp->target?"ACCEPT":"DROP");
            if(tmp->anyprot == true) {
                printk("      %-4s", "all");
            }
            else {
                switch(tmp->prot) {
                    case IPPROTO_TCP:
                        printk("      %-4s", "tcp");
                        break;
                    case IPPROTO_UDP:
                        printk("      %-4s", "udp");
                        break;
                    default:
                        printk("      %-4s", "icmp");
                        break;
                }
            }
            printk(" --  ");


            if(tmp->src.anyaddr) {
                //printk("  %s", "anywhere");
                strcpy(sinput, "anywhere");
            }
            else {
                //printk("  %s", addr_inet(tmp->src.addr));
                strcpy(sinput, addr_inet(tmp->src.addr));
                if(tmp->src.mask) {
                    //printk("/%d", tmp->src.mask);
                    strcat(sinput, "/");
                    strcat(sinput, itostr(tmp->src.mask));
                }
            }
            if(tmp->anysport == false) {
                //printk(":%-4d", tmp->sport);
                strcat(sinput, ":");
                strcat(sinput, itostr(tmp->sport));
            }
            printk("%-27s", sinput);


            if(tmp->dst.anyaddr) {
                //printk("  %s", "anywhere");
                strcpy(dinput, "anywhere");
            }
            else {
                //printk("  %s", addr_inet(tmp->dst.addr));
                strcpy(dinput, addr_inet(tmp->dst.addr));
                if(tmp->dst.mask) {
                    //printk("/%d", tmp->src.mask);
                    strcat(dinput, "/");
                    strcat(dinput, itostr(tmp->dst.mask));
                }
            }
            if(tmp->anydport == false) {
                //printk(":%-4d", tmp->sport);
                strcat(dinput, ":");
                strcat(dinput, itostr(tmp->dport));
            }
            printk("%-27s", dinput);
            memset(sinput, '\0', sizeof(sinput));
            memset(dinput, '\0', sizeof(dinput));

            if(tmp->tm.valid) {
                printk("%d:%d:%d--%d:%d:%d",
                    tmp->tm.btime.tm_hour, tmp->tm.btime.tm_min,
                    tmp->tm.btime.tm_sec,
                    tmp->tm.etime.tm_hour, tmp->tm.etime.tm_min,
                    tmp->tm.etime.tm_sec);
            }
            else {
                printk("%s", "anytime");
            }
            printk("\n");
        }
    }
}


void PrintRule() {
    printk("\n");
    printk(LIGHT_GREEN"-------------------------------------------------------------------------------\n"NONE);
    printk("Chain INPUT (policy ACCEPT)\n");
    printk("target      prot opt source                     destination                time\n");
    print_list(&rule_local_in);
    printk("\n");

    printk("Chain OUTPUT (policy ACCEPT)\n");
    printk("target      prot opt source                     destination                time\n");
    print_list(&rule_local_out);
    printk("\n");

    printk("Chain FORWARD (policy ACCEPT)\n");
    printk("target      prot opt source                     destination                time\n");
    print_list(&rule_forward);
    printk(LIGHT_GREEN"-------------------------------------------------------------------------------\n"NONE);
    printk("\n");



}

int rule_node_add(struct user_rule *rule_in, int flag) {
    struct rule *p;

    p = (struct rule *)kmalloc(sizeof(struct rule), GFP_KERNEL);
    if(strlen(rule_in->saddr) != 0) {
        p->src.anyaddr = false;
        if(strstr(rule_in->saddr, "/") != NULL) {
            char *saddr = rule_in->saddr;
            p->src.addr = inet_addr(strsep(&saddr, "/"));
            p->src.mask = strtoi(saddr);
        }
        else {
            p->src.addr = inet_addr(rule_in->saddr);
            p->src.mask = 0;
        }
    }
    else {
        p->src.anyaddr = true;
    }

    if(strlen(rule_in->sport)) {
        p->anysport = false;
        p->sport = strtoi(rule_in->sport);
    }
    else {
        p->anysport = true;
    }


    if(strlen(rule_in->daddr) != 0) {
        p->dst.anyaddr = false;
        if(strstr(rule_in->daddr, "/") != NULL) {
            char *daddr = rule_in->daddr;
            p->dst.addr = inet_addr(strsep(&daddr, "/"));
            p->dst.mask = strtoi(daddr);
        }
        else {
            p->dst.addr = inet_addr(rule_in->daddr);
            p->dst.mask = 0;
        }
    }
    else {
        p->dst.anyaddr = true;
    }

    if(strlen(rule_in->dport) == 0) {
        p->anydport = true;
    }
    else {
        p->anydport = false;
        p->dport = strtoi(rule_in->dport);
    }

    switch (rule_in->prot[0]) {
        case 't':
            p->prot = IPPROTO_TCP;
            p->anyprot  = false;
            break;
        case 'u':
            p->prot = IPPROTO_UDP;
            p->anyprot  = false;
            break;
        case 'i':
            p->prot == IPPROTO_ICMP;
            p->anyprot  = false;
            break;
        default:
            p->anyprot = true;

    }

    /*
    if(strcmp(rule_in->prot, "tcp") == 0) {
        p->prot = IPPROTO_TCP;
        p->anyprot  = false;
    }
    else if(strcmp(rule_in->prot, "udp") == 0) {
        p->prot = IPPROTO_UDP;
        p->anyprot  = false;
    }
    else if(strcmp(rule_in->prot, "icmp") == 0) {
        p->prot == IPPROTO_ICMP;
        p->anyprot  = false;
    }
    else {
        p->anyprot = true;
    }*/

    p->target = rule_in->target;
    if(strlen(rule_in->_time)) {
        sscanf(rule_in->_time, "%d:%d:%d--%d:%d:%d",
                        &p->tm.btime.tm_hour, &p->tm.btime.tm_min,
                        &p->tm.btime.tm_sec,
                        &p->tm.etime.tm_hour, &p->tm.etime.tm_min,
                        &p->tm.etime.tm_sec);
        p->tm.valid = true;
    }
    else {
        p->tm.valid = false;
    }

    if(rule_in->chain == INPUT) {
        if(flag == 1) {
            list_add(&(p->list), &rule_local_in);
        }
        else {
            list_add_tail(&(p->list), &rule_local_in);
        }
    }
    else if(rule_in->chain == OUTPUT) {
        if(flag == 1) {
            list_add(&(p->list), &rule_local_out);
        }
        else {
            list_add_tail(&(p->list), &rule_local_out);
        }
    }
    else {
        if(flag == 1) {
            list_add(&(p->list), &rule_forward);
        }
        else {
            list_add_tail(&(p->list), &rule_forward);
        }
    }

    return 0;
}

int rule_node_fulsh(struct user_rule *rule_in) {
    if(rule_in->chain == INPUT) {
        listfree(&rule_local_in);
    }
    else if(rule_in->chain == OUTPUT) {
        listfree(&rule_local_out);
    }
    else if(rule_in->chain == FORWARD) {
        listfree(&rule_forward);
    }
    else {
        listfree(&rule_local_in);
        listfree(&rule_forward);
        listfree(&rule_local_out);
    }

    return 0;
}

int rule_node_delete(struct user_rule *rule_in) {
    struct list_head list_in;
    struct list_head *pos = NULL, *q = NULL;
    struct rule *tmp;
    int count = 0;

    switch(rule_in->chain) {
        case INPUT:
            list_in = rule_local_in;
            break;
        case OUTPUT:
            list_in = rule_local_out;
            break;
        case FORWARD:
            list_in = rule_forward;
            break;
        default:
            break;
    }
    
    list_for_each_safe(pos, q, &list_in) {
        count++;
        printk("%d", rule_in->line);
        if(count == rule_in->line) {
            tmp = list_entry(pos, struct rule, list);
            list_del(pos);
            kfree(tmp);
            break;
        }

    }

    return 0;
}
/*
char* sprint_list(struct list_head *list_in, struct file *buf) {
    struct rule *tmp;
    char sinput[100];
    char dinput[100];
    char *buffer = (char *)kmalloc(100 * sizeof(char), GFP_KERNEL);

    if(!list_empty(list_in)) {
        list_for_each_entry(tmp, list_in, list) {
            sprintf(buffer, "%-6s", tmp->target?"ACCEPT":"DROP");
            if(tmp->anyprot == true) {
                sprintf(buffer, "      %-4s", "all");
            }
            else {
                switch(tmp->prot) {
                    case IPPROTO_TCP:
                        sprintf(buffer, "      %-4s", "tcp");
                        break;
                    case IPPROTO_UDP:
                        sprintf(buffer, "      %-4s", "udp");
                        break;
                    default:
                        sprintf(buffer, "      %-4s", "icmp");
                        break;
                }
            }
            sprintf(buffer, " --  ");


            if(tmp->src.anyaddr) {
                //printk("  %s", "anywhere");
                strcpy(sinput, "anywhere");
            }
            else {
                //printk("  %s", addr_inet(tmp->src.addr));
                strcpy(sinput, addr_inet(tmp->src.addr));
                if(tmp->src.mask) {
                    //printk("/%d", tmp->src.mask);
                    strcat(sinput, "/");
                    strcat(sinput, itostr(tmp->src.mask));
                }
            }
            if(tmp->anysport == false) {
                //printk(":%-4d", tmp->sport);
                strcat(sinput, ":");
                strcat(sinput, itostr(tmp->sport));
            }
            sprintf(buffer, "%-27s", sinput);


            if(tmp->dst.anyaddr) {
                //printk("  %s", "anywhere");
                strcpy(dinput, "anywhere");
            }
            else {
                //printk("  %s", addr_inet(tmp->dst.addr));
                strcpy(dinput, addr_inet(tmp->dst.addr));
                if(tmp->dst.mask) {
                    //printk("/%d", tmp->src.mask);
                    strcat(dinput, "/");
                    strcat(dinput, itostr(tmp->dst.mask));
                }
            }
            if(tmp->anydport == false) {
                //printk(":%-4d", tmp->sport);
                strcat(dinput, ":");
                strcat(dinput, itostr(tmp->dport));
            }
            sprintf(buffer, "%-27s", dinput);
            memset(sinput, '\0', sizeof(sinput));
            memset(dinput, '\0', sizeof(dinput));

            if(tmp->tm.valid) {
                sprintf(buffer, "%d:%d:%d--%d:%d:%d",
                    tmp->tm.btime.tm_hour, tmp->tm.btime.tm_min,
                    tmp->tm.btime.tm_sec,
                    tmp->tm.etime.tm_hour, tmp->tm.etime.tm_min,
                    tmp->tm.etime.tm_sec);
            }
            else {
                sprintf(buffer, "%s", "anytime");
            }
            sprintf(buffer, "\n");
            copy_to_user((void *)buf, buffer, 100);
        }
    }
}

int rule_save(struct file *file) {
    sprint_list(&rule_local_in, file);
    sprint_list(&rule_local_out, file);
    sprint_list(&rule_forward, file);

    return 0;
}
*/
int file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0;
    struct user_rule *buff = (struct user_rule*)kmalloc(sizeof(struct user_rule), GFP_KERNEL);
    switch(cmd) {
        case RULE_LIST:
            PrintRule();
            break;
        case RULE_APPEND:
            copy_from_user(buff, (struct user_rule*)arg, sizeof(struct user_rule));
            ret = rule_node_add(buff, 0);
            break;
        case RULE_INSERT:
            copy_from_user(buff, (struct user_rule*)arg, sizeof(struct user_rule));
            ret = rule_node_add(buff, 1);
            break;
        case RULE_FULSH:
            copy_from_user(buff, (struct user_rule*)arg, sizeof(struct user_rule));
            ret = rule_node_fulsh(buff);
            break;
        case RULE_DELETE:
            copy_from_user(buff, (struct user_rule*)arg, sizeof(struct user_rule));
            printk("%d", buff->line);
            ret = rule_node_delete(buff);
            break;
        case RULE_SAVE:
            //ret = rule_save(file);
            break;
    }

    return ret;
}


/*
 * @function open file
 * @para {struct inode *} inode
 * @para {struct file *} file
 * @return {int}
 */
int file_open(struct inode *inode, struct file *file) {
    struct mem_dev *dev;
    int num;

    //获取次设备号
    num = MINOR(inode->i_rdev);
    if(num > MEMDEV_NR_DEVS) {
        return -ENODEV;
    }
    dev = &mem_devp[num];

    //将设备描述结构指针赋值给文件私有数据指针
    file->private_data = dev;

    return 0;
}

/*
 * @function release file
 * @para {struct inode *} inode
 * @para {struct file *} file
 * @return {int}
 */
int file_release(struct inode *inode, struct file *file) {
    return 0;
}

/*
 * @function read
 * @para {struct file *} file
 * @para {char *} buf
 * @para {size_t} size
 * @para {loff_t *} ppos
 * @return {ssize_t}
 */
ssize_t file_read(struct file *file, char __user *buf,
        size_t size, loff_t *ppos) {
    unsigned int p = *ppos;
    unsigned int count = size;

    struct mem_dev *dev = file->private_data;   //获得设备结构体指针
    //判断读位置是否有效
    if(p >= MEMDEV_SIZE) {
        return 0;
    }
    if(count > MEMDEV_SIZE - p) {
        count = MEMDEV_SIZE - p;
    }

    //读取数据到用户空间
    if(copy_to_user(buf, (void *)(dev->data + p), count)){
        return -EFAULT;
    }
    *ppos += count;

    printk(KERN_INFO"read %d byte(s) from %d\n", count, p);
    printk("<kernel>read content is \n[%s]\n", buf);
    return count;
}

/*
 * @function write
 * @para {struct file *} file
 * @para {char *} buf
 * @para {size_t} size
 * @para {loff_t *} ppos
 * @return {ssize_t}
 */
ssize_t file_write(struct file *file, const char __user *buf,
        size_t size, loff_t *ppos) {
    unsigned int p = *ppos;
    unsigned int count = size;
    struct mem_dev *dev;
    struct list_head *pos, *q;
    struct rule *tmp;
    //int nline, off, ret, i;
    //char *buffer;
    //char saddr[30], daddr[30];

    dev = file->private_data;  //获得设备结构体指针

    if(p >= MEMDEV_SIZE) {
        return 0;
    }
    if(count > MEMDEV_SIZE - p) {
        count = MEMDEV_SIZE - p;
    }

    //从用户空间写入数据
    if(copy_from_user(dev->data + p, buf, count)) {
        return -EFAULT;
    }
    *ppos += count;
    printk("dev_rule_write: success\n");
    printk(KERN_INFO"written %d byte(s) from %d\n", count, p);
    printk("<kernel>written content is \n[%s]\n", dev->data + p);

    list_for_each_safe(pos, q, &rule_local_in){
        tmp = list_entry(pos, struct rule, list);
        list_del(pos);
        kfree(tmp);
    }
    /*
    buffer = dev->data + p;
    nline = 0;
    off = 0;
    sscanf(buffer, "%d%n", &nline, &off);
    //printk("%d   %d\n", nline, off);
    buffer += off;
    for(i = 0; i < nline; ++i) {
        if((tmp = (struct rule*)kzalloc(sizeof(struct rule), GFP_KERNEL)) == NULL){
            printk("Error: kmalloc fail.\n");
            break;
        }
        ret = sscanf(buffer, "%s /%hhu:%hu, %s /%hhu:%hu, %hhu, %hu, %d:%d:%d, %d:%d:%d, %hu%n",
                        saddr, &tmp->src.mask, &tmp->src.port,
                        daddr, &tmp->dst.mask, &tmp->dst.port,
                        &tmp->prot,
                        &tmp->tm.valid,
                        &tmp->tm.btime.tm_hour, &tmp->tm.btime.tm_min, &tmp->tm.btime.tm_sec,
                        &tmp->tm.etime.tm_hour, &tmp->tm.etime.tm_min, &tmp->tm.etime.tm_sec,
                        &tmp->target, &off);
        tmp->src.addr = inet_addr(saddr);
        tmp->dst.addr = inet_addr(daddr);
        printk("%s/%hhu:%hu, %s/%hhu:%hu, %hhu, %hu, %02d:%02d:%02d, %02d:%02d:%02d, %hu\n",
                saddr, tmp->src.mask, tmp->src.port,
                daddr, tmp->dst.mask, tmp->dst.port,
                tmp->prot,
                tmp->tm.valid,
                tmp->tm.btime.tm_hour, tmp->tm.btime.tm_min, tmp->tm.btime.tm_sec,
                tmp->tm.etime.tm_hour, tmp->tm.etime.tm_min, tmp->tm.etime.tm_sec,
                tmp->target);
        if(ret < 15) {
            printk("sscanf fail , only complete %d scanfs\n", ret);
        }
        buffer += off;
        list_add_tail(&(tmp->list), &rule_local_in);
    }
    */
    return count;
}

/*
 * @function seek for file
 * @para {struct file *} file
 * @para {loff_t *} offset
 * @para {int} whence
 * @return {loff_t}
 */
loff_t file_llseek(struct file *file, loff_t offset, int whence) {
    loff_t newpos;
    switch(whence){
        case 0: /* SEEK_SET */
            newpos = offset;
            break;
        case 1: /* SEEK_CUR */
            newpos = file->f_pos + offset;
            break;
        case 2: /* SEEK_END */
            newpos = MEMDEV_SIZE -1 + offset;
            break;
        default: /* can't happen */
            return -EINVAL;
    }

    if((newpos < 0) || (newpos > MEMDEV_SIZE)) {
        return -EINVAL;
    }
    file->f_pos = newpos;  //返回当前文件位置

    return newpos;
}


int dev_init(void) {
    int ret = 0;
    int i;

    devno = MKDEV(MEMDEV_MAJOR, MEMDEV_MAIOR);

    //如果主设备号不为0，使用静态申请一个设备号
    if(major) {
        ret = register_chrdev_region(devno, MEMDEV_NR_DEVS, "chardev");
        if(ret < 0) {
            // fail
            ret = alloc_chrdev_region(&devno, 0, MEMDEV_NR_DEVS, "chardev");
            if(ret < 0) {
                printk(LIGHT_RED"dev_init: register devno error!\n"NONE);
                return ret;
            }
            printk(LIGHT_BLUE"dynamic1 register devno success!\n"NONE);
            major = MAJOR(devno);
            minor = MINOR(devno);
        }
        else {
            printk(LIGHT_BLUE"static register devno success!\n"NONE);
        }
    }
    //否则由内核动态分配
    else {
        ret = alloc_chrdev_region(&devno, 0, MEMDEV_NR_DEVS, "chardev");
        if(ret < 0) {
            printk(LIGHT_RED"dev_init: register devno error!\n"NONE);
            return ret;
        }
        printk(LIGHT_BLUE"dynamic2 register devno success!\n"NONE);
        major = MAJOR(devno);
        minor = MINOR(devno);
    }
    printk("successfully register an devno %x!\n", devno);
    printk("<0>""major[%d] minor[%d]\n", major, minor);

    //2.注册设备
    //初始化cdev结构
    cdev_init(&iptable_cdev, &rule_fops);
    iptable_cdev.owner = THIS_MODULE;   //指定模块的所属
    iptable_cdev.ops = &rule_fops;

    // 添加cdev到内核
    ret = cdev_add(&iptable_cdev, devno, MEMDEV_NR_DEVS);
    if(ret < 0) {
        printk(LIGHT_RED"cdev_add error!\n"NONE);
        unregister_chrdev_region(devno, MEMDEV_NR_DEVS);
        //return -ENODEV;
        return ret;
    }
    printk(LIGHT_BLUE"hello kernel, cdev_add success!\n"NONE);

    /* 为设备描述结构分配内存*/
    mem_devp = kmalloc(MEMDEV_NR_DEVS * sizeof(struct mem_dev), GFP_KERNEL);
    if(!mem_devp) {  //申请失败
        printk(LIGHT_RED"mem_dev kmalloc error!\n"NONE);
        unregister_chrdev_region(devno, MEMDEV_NR_DEVS);
        return -ENOMEM;
    }
    memset(mem_devp, 0, sizeof(struct mem_dev));  //新申请的内存做初始化工作

    /*为设备分配内存*/
    for(i = 0; i < MEMDEV_NR_DEVS; i++) {
        mem_devp[i].size = MEMDEV_SIZE;
        mem_devp[i].data = kmalloc(MEMDEV_SIZE, GFP_KERNEL);//分配内存给两个设备
        memset(mem_devp[i].data, 0, MEMDEV_SIZE);//初始化新分配到的内存
    }
    return ret;
}

void dev_exit(void){
    //从内核中删除cdev
    cdev_del(&iptable_cdev);
    //注销设备号
    unregister_chrdev_region(devno, MEMDEV_NR_DEVS);
    printk("good bye kernel, dev exit ...\n");
}
