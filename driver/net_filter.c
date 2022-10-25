#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>

static struct nf_hook_ops *nfho = NULL;

static bool isHttpPacket(struct sk_buff *skb)
{
    struct tcphdr *tcph = NULL;
    struct iphdr *iph = NULL;
    int tcp_payload_size = 0;
    char *tcp_payload = NULL;
    int i=0;
    int ip_and_tcp_header_length = 0;

    if(NULL == skb) return false;
 
    iph = ip_hdr(skb);
    if(NULL == iph) return false;

    tcph = tcp_hdr(skb);
    if(NULL == tcph) return false;

    tcp_payload = (char *)((char*)tcph + (int)(tcph->doff * 4));

    ip_and_tcp_header_length = (int)((char*)tcp_payload - (char*)iph);
    tcp_payload_size = (int)(ntohs(iph->tot_len) - ip_and_tcp_header_length);

    //printk(KERN_INFO "net_filter: TCP data size is[%d]", tcp_payload_size);

    if(80 == ntohs(tcph->dest))
    {
        if(tcp_payload_size >= 50)
        {
            for(i=0; i<32; i++)
            {
                // Debug printing TCP payload
                printk(KERN_INFO "net_filter: [%c] \n", tcp_payload[i]);
            }
        }
   }

    if(80 == ntohs(tcph->dest))
    {
        printk(KERN_INFO "net_filter: HTTP Port! Data size [%d]\n", tcp_payload_size);
        return true;
    }

    return false;
}

static unsigned int hfunc(
    void *priv, 
    struct sk_buff *skb, 
    const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    struct tcphdr *tcph;
       
    if (!skb)
    {
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    
    if(iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);
        //printk(KERN_INFO "net_filter: Handling TCP packet. dst_port=[%hu]", ntohs(tcph->dest));

        isHttpPacket(skb);
    
        return NF_ACCEPT;
    }
    
    else if(iph->protocol == IPPROTO_UDP)
    {  
        udph = udp_hdr(skb);
        //printk(KERN_INFO "net_filter: Handling UDP packet. dst_port=[%hu]", ntohs(udph->dest));
        return NF_ACCEPT;
    }
    
    return NF_DROP;
}

static int __init LKM_init(void)
{
    nfho = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    
    /* Initialize netfilter hook */
    nfho->hook = (nf_hookfn*)hfunc;        /* hook function */
    //nfho->hooknum = NF_INET_PRE_ROUTING;   /* received packets */
    nfho->hooknum = NF_INET_LOCAL_OUT;   /* sent packets */

    
    nfho->pf = PF_INET;                    /* IPv4 */
    nfho->priority = NF_IP_PRI_FIRST;      /* max hook priority */
    
    nf_register_net_hook(&init_net, nfho);
    
    return 0;
}

static void __exit LKM_exit(void)
{
    nf_unregister_net_hook(&init_net, nfho);
    kfree(nfho);
}

module_init(LKM_init);

module_exit(LKM_exit);

MODULE_LICENSE("GPL");
