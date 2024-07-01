import scapy.all as scapy
import os

def get_mac_address(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def detect_arp_spoofing(gateway_ip):
    initial_mac = get_mac_address(gateway_ip)
    if initial_mac is None:
        print("No se pudo obtener la dirección MAC inicial del gateway.")
        return
    print(f"Dirección MAC inicial del gateway: {initial_mac}")

    while True:
        current_mac = get_mac_address(gateway_ip)
        if current_mac != initial_mac:
            print("ARP spoofing detectado")
            print(f"Dirección MAC cambiada de {initial_mac} a {current_mac}")
            break
        else:
            print("No se detectó ARP spoofing...")

router_ip  = os.popen("ip route | grep default").read().strip()
gateway_ip = router_ip.split()[2]
detect_arp_spoofing(gateway_ip)