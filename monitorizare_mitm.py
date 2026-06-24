import scapy.all as scapy    #importam biblioteca Scapy pentru interceptia (sniffing) 
                             #si crearea de pachete de rețea personalizate

def get_mac(ip):

    """obtinem MAC-ul real al unui IP prin broadcast"""
    arp_request = scapy.ARP(pdst=ip)  #creeaza un pachet ARP prin care intreaba cine detine IP-ul tinta
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #creeaza un pachet ETHERNET directionat catre toate dispozitivele din retea (broadcast)
    arp_request_broadcast = broadcast/arp_request #combina stratul ETHERNET (plicul) cu stratul ARP (scrisoarea)
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0] #trimite pachetul si salveaza doar raspunusrile primite
    return answered_list[0][1].hwsrc if answered_list else None #extrage si returneaza adresa MAC din raspunsul primit


def process_sniffed_packet(packet):  #creierul care decide daca suntem atacati sau nu

    """analizeaza pachetele si detecteaza anomaliile de Layer 2"""
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2: #verificam daca pachetul este un raspuns ARP (Reply)
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)  #aflam adresa MAC reala a celui care a trimis pachetul
            response_mac = packet[scapy.ARP].hwsrc      #citim adresa mac declarata in pachetul interceptat

            if real_mac != response_mac:
                print(f"\n[!] ALERTA MITM: Dispozitivul cu IP {packet[scapy.ARP].psrc} este atacat!")
                print(f"[*] MAC Real: {real_mac} | MAC Atacator: {response_mac}")
        except:
            pass



print("[+] Sistem de monitorizare activ. Se cauta anomalii ARP...")
scapy.sniff(store=False, prn=process_sniffed_packet, filter="arp") #este butonul de ON al programului meu
#porneste monitorizarea continua, filtrand doar pachetele ARP si procesandu-le in timp real