



# # Firewall as a Linux Kernel Module (Netfilter)

## # What is the purpose of this repository?

**This repository was created for educational purposes. This repository may help you learn how to create a Linux Kernel Module, filter a network packet in the Kernel Module, and so on.**

## Prerequisite

Before diving into this repository, you should read these articles:

 - [**Understanding Network Packets: IP Header, UDP Header**](https://adil.medium.com/understanding-network-packets-ip-header-udp-header-a672398553d0)
 - [**How To Use IPTables to Block a Specific DNS Request?**](https://adil.medium.com/how-to-use-iptables-to-block-a-specific-dns-request-2dfb5ca7340b)
 - [**How to Write a Simple Linux Kernel Module?**](https://adil.medium.com/how-to-write-a-simple-linux-kernel-module-bc3f981093b4)

## # Who uses Netfilter?

Netfilter is a framework provided by the Linux. On top of **netfilter** there are **iptables**, **nftables** and **ipvs** are being developed.

So yes, you can develop your own firewall using the Netfilter framework.

## # What will I learn from this repository?

**Part 1**

 - How to build an out-of-tree Linux Kernel Module?
 - How to deploy the module to Linux Kernel?
 - How can you access the module's logs?

**Part 2**

 - How to process or filter network packages in the Linux Kernel Module using Netfilter?
 - How to print an IP address in the Kernel Module?
 - To which network protocol does the package belong?

**Part 3**

 - How may a network package be filtered and blocked?
 - How may all UDP packets created on your device be blocked?

**Part 4**

 - How can you prevent your device from sending any DNS requests in UDP packets?
 - `dig A twitter.com`

**Part 5**

- How could MX DNS queries in UDP packets that your device sends be blocked?
- `dig mx yahoo.com`

**Part 6**

- Is there a way to stop your device from sending UDP packets that contain MX DNS requests for only *google.com*?
- `dig mx google.com`

**Part 7**

- In the same way that tcpdump prints hexadecimal data, how can you print UDP packet?
- `tcpdump -i any port 53 -Xn`

## How to build a module and deploy it to Linux Kernel?

Each module has a Makefile. All you need to do is develop the module and deploy it to the Linux kernel.

Go to the correct folder:

`cd part_1`

Build the module:

`make`

Make sure that `packagefilter.ko` is generated:

`ls packagefilter.ko`

Deploy it to the Linux Kernel:

`insmod packagefilter.ko`

Ensure that your module is deployed to the Linux kernel.

`lsmod | grep packagefilter`

Check the logs:

`tail -f /var/log/syslog`

or

`dmesg`

Remove the module from the Linux Kernel:

`rmmod packagefilter`

<a href="https://asciinema.org/a/647411" target="_blank"><img src="https://asciinema.org/a/647411.svg" /></a>

