#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho;

unsigned int custom_network_filter(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state) {

  struct iphdr *iph = ip_hdr(skb);
  char protocol[17];

  if (iph->protocol == IPPROTO_TCP) { // Protocol number is 6
    strcpy(protocol, "TCP");
  } else if (iph->protocol == IPPROTO_UDP) { // Protocol number is 17
    strcpy(protocol, "UDP");
  } else if (iph->protocol == IPPROTO_ICMP) { // Protocol number is 1
    strcpy(protocol, "ICMP");
  } else {
    strcpy(protocol, "Another protocol");
  }

  pr_info("Source IP: %pI4\n", &iph->saddr);
  pr_info("Destination IP: %pI4\n", &iph->daddr);
  pr_info("Protocol Number: %d\n", iph->protocol);
  pr_info("Protocol Name: %s\n", protocol);
  pr_info("--\n");

  return NF_ACCEPT;
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
