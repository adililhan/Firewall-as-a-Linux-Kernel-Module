#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>

static struct nf_hook_ops nfho;

#define DNS_PORT 53
#define DNS_PAYLOAD_OFFSET 41
#define DNS_MX_QTYPE_DECIMAL 15 // 15 is the decimal value for MX QTYPE

unsigned int custom_network_filter(void *priv, struct sk_buff *skb,
                                   const struct nf_hook_state *state) {

  struct iphdr *iph = ip_hdr(skb);
  struct udphdr *udph;

  short port, dns_payload_cursor, dns_qtype_offset;
  uint8_t *network_packet;
  int dns_qtype;

  if (iph->protocol != IPPROTO_UDP) {
    return NF_ACCEPT;
  }

  udph = udp_hdr(skb);
  port = htons(udph->dest);

  if (port != DNS_PORT) {
    return NF_ACCEPT;
  }

  dns_payload_cursor = DNS_PAYLOAD_OFFSET;
  network_packet = skb_network_header(skb);

  if (network_packet[dns_payload_cursor] == 0) {
    // Handle unusual cases
    // example: dig mx .
    return NF_ACCEPT;
  }

  // Iterate through DNS Payload
  while (true) {
    if (network_packet[dns_payload_cursor] == 0 &&
        network_packet[dns_payload_cursor + 1] == 0) {
      // Break when end of label is found
      break;
    }
    dns_payload_cursor++;
  }

  // Get the DNS QTYPE
  dns_qtype_offset = dns_payload_cursor + 2;
  dns_qtype = network_packet[dns_qtype_offset];

  if (DNS_MX_QTYPE_DECIMAL == dns_qtype) {
    pr_info("Dropping the MX DNS query in the UDP packet.\n");
    pr_info("Destination IP: %pI4\n", &iph->daddr);
    pr_info("Destination Port Src: %hu\n", htons(udph->dest));
    pr_info("--\n");
    return NF_DROP;
  }

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
