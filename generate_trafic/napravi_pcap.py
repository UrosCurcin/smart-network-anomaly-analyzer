from pathlib import Path
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

print("Generišem čiste Ethernet/IP/TCP pakete...")

normalni_paketi = [
    Ether(type=0x0800)
    / IP(src="192.168.1.5", dst="8.8.8.8")
    / TCP(sport=50000, dport=443, flags="S")
    for _ in range(250)
]

output_path = Path("cisti_test.pcap")
wrpcap(str(output_path), normalni_paketi)
print(f"Uspelo! Kreiran je fajl na putanji: {output_path.resolve()}")