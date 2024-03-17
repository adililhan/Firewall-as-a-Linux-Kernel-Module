#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>

static struct nf_hook_ops nfho;

#define DNS_PORT 53

unsigned int custom_network_filter(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state) {

  struct iphdr *iph = ip_hdr(skb);
  struct udphdr *udph;
  short port;

  if (iph->protocol != IPPROTO_UDP) {
    return NF_ACCEPT;
  }

  udph = udp_hdr(skb);
  port = htons(udph->dest);

  if (port != DNS_PORT) {
    return NF_ACCEPT;
  }

  pr_info("The DNS query in the UDP packet is dropped.\n");
  pr_info("Destination IP: %pI4\n", &iph->daddr);
  pr_info("Destination Port Src: %hu\n", htons(udph->dest));
  pr_info("--\n");

  return NF_DROP;
}

static int __init mod_init(void) {
  nfho.hook = custom_network_filter;
  nfho.hooknum = NF_INET_POST_ROUTING;
  nfho.pf = NFPROTO_INET;
  nfho.priority = NF_IP_PRI_FIRST;
  nf_register_net_hook(&init_net, &nfho);
  pr_info("Network packet filtering module initalized\n");
  return 0;
}

static void __exit mod_exit(void) {
  nf_unregister_net_hook(&init_net, &nfho);
  printk(KERN_INFO "Network packet filtering module removed\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
