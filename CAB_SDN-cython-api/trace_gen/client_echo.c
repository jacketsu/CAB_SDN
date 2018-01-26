#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/fs.h>
#include <linux/netfilter.h>
#include <asm/uaccess.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/tcp.h>

/* classify ecn 11 packet  */

static struct nf_hook_ops nfho_pre;
char d_name[] = "p7p3";
unsigned char srv_mac[ETH_ALEN] = {0xa0,0x36,0x9f,0x71,0x14,0x04};


#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,12,62))
    unsigned int pre_hook_func(unsigned int hooknum, struct sk_buff **skb,
                               const struct net_device *in, const struct net_device *out,
                               int (*okfn)(struct sk_buff *))    // kernel 3.12
#else
    unsigned int pre_hook_func(const struct nf_hook_ops *ops, struct sk_buff *skb,
                               const struct net_device *in,
                               const struct net_device *out, int(*okfn)(struct sk_buff *))
#endif
{
    if (skb->len < 20)
        return NF_ACCEPT;

    if (!strncmp(in->name, d_name, 4)){
        unsigned int version;

        version = (*(uint32_t *)(skb->data)); 
        printk("recev something %u\n", version);

        if ((version & 96) == 96){
            struct ethhdr * ethh;
            struct net_device * eth_dev;

            printk("recv ipv6 pkt... echoing\n");
            
            skb->pkt_type = PACKET_OUTGOING;
            eth_dev = dev_get_by_name(&init_net, d_name);
            skb->dev = eth_dev;
            ethh = (struct ethhdr *) skb_push(skb, ETH_HLEN);
            skb_reset_mac_header(skb);
            skb->protocol = ethh->h_proto = htons(ETH_P_IP);
            memcpy (ethh->h_source, eth_dev->dev_addr, ETH_ALEN);
            memcpy (ethh->h_dest, srv_mac, ETH_ALEN);

            dev_hold(skb->dev);
            dev_put(skb->dev);
            dev_queue_xmit(skb);
            return NF_STOLEN;
        } 
    }

    return NF_ACCEPT;
}


static int __init cli_echo_init(void) {
    nfho_pre.hook = pre_hook_func;           // function to call when conditions below met
    nfho_pre.hooknum = NF_INET_PRE_ROUTING;  // called right after packet recieved, first hook in Netfilter
    nfho_pre.pf = PF_INET6;                   // IPV4 packets
    nfho_pre.priority = NF_IP_PRI_FIRST;     // set to highest priority over all other hook functions
    nf_register_hook(&nfho_pre);             // register hook

    printk("pre hook registered\n");

    return 0;
}

static void __exit cli_echo_exit(void) {
    nf_unregister_hook(&nfho_pre);
    printk("pre hook unregistered\n");
}

module_init(cli_echo_init);
module_exit(cli_echo_exit);
