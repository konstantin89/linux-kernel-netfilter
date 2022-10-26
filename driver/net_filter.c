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

const unsigned char *get_ipv4_payload(const struct iphdr *ipHeader)
{
    int ipHeaderLenInBytes = 4 * ipHeader->ihl;
    const unsigned char *transportHeader = (const unsigned char*)(((const char*)(ipHeader)) + ipHeaderLenInBytes);
    return transportHeader;
}

const struct tcphdr *get_tcp_header_from_ipv4_header(const struct iphdr *ipHeader)
{
    const struct tcphdr *tcpHeader = (const struct tcphdr *)get_ipv4_payload(ipHeader);
    return tcpHeader;
}

const unsigned char *get_tcp_payload(const struct tcphdr *tcp_header)
{
    const unsigned char *tcp_payload_start = (const unsigned char*)tcp_header + (4 * tcp_header->doff);
    return tcp_payload_start;
}

int get_tcp_payload_size(const struct iphdr *ip_header)
{
    const struct tcphdr *tcph = get_tcp_header_from_ipv4_header(ip_header);
    const unsigned char *tcp_payload_start = get_tcp_payload(tcph);
    int payload_length = ntohs(ip_header->tot_len) - (tcp_payload_start - (const unsigned char*)ip_header);
    return payload_length;
}

static bool isHttpPacket(struct sk_buff *skb)
{
    struct tcphdr *tcph = NULL;
    struct iphdr *iph = NULL;
    int tcp_payload_size = 0;
    char *tcp_payload = NULL;

    if(NULL == skb) return false;
 
    iph = ip_hdr(skb);
    if(NULL == iph) return false;

    tcph = tcp_hdr(skb);
    if(NULL == tcph) return false;

    tcp_payload = get_tcp_payload(tcph);
    tcp_payload_size = get_tcp_payload_size(iph);

    if(tcp_payload_size < 4) return false;

    // Response HTTP
    if (tcp_payload[0] != 'H' || tcp_payload[1] != 'T' || tcp_payload[2] != 'T' || tcp_payload[3] != 'P') 
    {
        return false;
    }

    // Outgoing GET request
    if (tcp_payload[0] != 'G' || tcp_payload[1] != 'E' || tcp_payload[2] != 'T') 
    {
        return false;
    }

    printk(KERN_INFO "net_filter: Got HTTP packet! TCP payload size is[%d]", tcp_payload_size);

    return true;
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

        bool isHttp = isHttpPacket(skb);
        // This will drop all HTTP packets
        //if(isHttp) return NF_DROP;
    
        return NF_ACCEPT;
    }
    
    else if(iph->protocol == IPPROTO_UDP)
    {  
        udph = udp_hdr(skb);
        //printk(KERN_INFO "net_filter: Handling UDP packet. dst_port=[%hu]", ntohs(udph->dest));
        return NF_ACCEPT;
    }
    
    return NF_ACCEPT;
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
