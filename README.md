# ARP Cache Poisoning Attack in Perl

This script sends gratuitous ARP replies to given host and default gateway

## DISCLAIMER

This is for educational purposes ONLY. **I DO NOT encourage or promote any illegal activities.**

## Requirements

- [Net::ARP](https://metacpan.org/pod/Net::ARP)

## Usage

```
Usage:

$ sudo perl arp_poison.pl -i <interface> -t <IPv4 address> -g <IPv4 address>

Options:

        -i -interface <if name>  name of the network interface
        -t -target <IPv4>        IPv4 address of the target
        -g -gateway <IPv4>       IPv4 address of the default gateway
        -h -help                 prints this help and exits

Example:

$ sudo perl arp_poison.pl -i eth0 -t 192.168.1.100 -g 192.168.1.1
```

