from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap
import random


def generate_realistic_scenario(filename="realistic_traffic.pcap"):
    print("Sastavljam realni mrežni scenario...")

    packets = []

    # 1. Benigni web saobraćaj (Klijent 192.168.1.10 <-> Server 93.184.216.34 na portu 443)
    # Simuliramo 3-way handshake i prenos podataka u manjim prozorima
    for i in range(30):
        # Normalan TCP paket sa standardnom veličinom (npr. 500-1200 bajtova)
        pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=443, flags="PA", seq=i * 100,
                                                                ack=1) / ("A" * random.randint(200, 800))
        packets.append(pkt)

    # 2. Pozadinski DNS saobraćaj (UDP 53)
    for i in range(10):
        dns_pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=random.randint(40000, 60000), dport=53)
        packets.append(dns_pkt)

    # 3. Ubačena anomalija 1: Port Scan (Spoljni IP proverava portove)
    # Kratki SYN paketi bez uspostavljene sesije na više različitih portova
    for target_port in [22, 80, 443, 3389, 8080, 4444]:
        scan_pkt = IP(src="203.0.113.50", dst="192.168.1.10") / TCP(sport=51234, dport=target_port, flags="S")
        packets.append(scan_pkt)

    # Vraćamo se na normalan saobraćaj da model ne odlepi prerano
    for i in range(20):
        pkt = IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=54321, dport=443, flags="A", seq=3000 + i * 50,
                                                                ack=1) / ("B" * 100)
        packets.append(pkt)

    # 4. Ubačena anomalija 2: Data Exfiltration (Ogromni paketi ka nepoznatoj IP adresi)
    for i in range(15):
        exfil_pkt = IP(src="192.168.1.10", dst="198.51.100.99") / TCP(sport=54321, dport=9001, flags="PA") / (
                    "X" * 4000)
        packets.append(exfil_pkt)

    # Nasumično promešamo redosled da simuliramo stvarni mrežni drajver i asinhroni protok
    random.shuffle(packets)

    wrpcap(filename, packets)
    print(f"Uspelo! Generisan fajl '{filename}' sa ukupno {len(packets)} prepletenih paketa.")


if __name__ == "__main__":
    generate_realistic_scenario()