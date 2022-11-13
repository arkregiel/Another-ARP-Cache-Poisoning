#!/usr/bin/perl

use strict;
use warnings;
use Net::ARP;
use Getopt::Long;

our ($interface, $localMac, $localIp);

sub getInterfaceAddresses() {
    my $ifconf = `ifconfig $interface`;
    $ifconf =~ /inet (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/;
    my $ip = $1;
    my $mac = Net::ARP::get_mac($interface);
    return ($ip, $mac)
}

sub getRemoteMacAddress($) {
    my $ip = shift;

    Net::ARP::send_packet(
        $interface,
        $localIp,
        $ip,
        $localMac,
        'ff:ff:ff:ff:ff:ff',
        'request'
    );

    my $mac = Net::ARP::arp_lookup($interface, $ip);
    return $mac
}

sub sendGratuitousArpReply($$$$) {
    my ($srcIP, $srcMac, $destIP, $destMac) = @_;

    Net::ARP::send_packet(
        $interface,
        $srcIP,
        $destIP,
        $srcMac,
        $destMac,
        'reply'
    ) or warn "[!!] Cannot send ARP reply\n";
}

$interface = 'wlan0';
($localIp, $localMac) = &getInterfaceAddresses("wlan0");

print "IP: $localIp\nMAC: $localMac\n";