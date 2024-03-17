#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>

static struct nf_hook_ops nfho;

#define DNS_PORT 53

unsigned int custom_network_filter(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state) {

  uint8_t *network_packet;
  size_t len;
  int i, j;
  short port;

  struct iphdr *iph = ip_hdr(skb);
  struct udphdr *udph;

  if (iph->protocol != IPPROTO_UDP) {
    return NF_ACCEPT;
  }

  udph = udp_hdr(skb);
  port = htons(udph->dest);

  if (port != DNS_PORT) {
    return NF_ACCEPT;
  }

  if (skb_is_nonlinear(skb)) {
    len = skb->data_len;
  } else {
    len = skb->len;
  }

  network_packet = skb_network_header(skb);

  j = 1;

  for (i = 0; i < len; i++) {

    pr_cont("%02X ", network_packet[i]);

    if ((j++ % 10) == 0) {
      pr_cont("\n");
    }
  }
  pr_cont("\n");

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
