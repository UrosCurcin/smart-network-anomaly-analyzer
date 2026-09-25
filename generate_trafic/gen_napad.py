from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

print("Generišem kvalitetniji testni fajl...")

# Puno više normalnog saobraćaja da model ima šta da uči (500 paketa = 50 prozora)
normalni = [IP(src="192.168.1.5", dst="8.8.8.8") / TCP(sport=50000, dport=443, flags="S") for _ in range(500)]

# Hakerski saobraćaj sa drugog IP-a, sa ludim flegovima i ogromnim payload-om
napad = [IP(src="192.168.1.66", dst="8.8.8.8") / TCP(sport=666, dport=80, flags="SF") / ("X" * 5000) for _ in range(100)]

wrpcap("meovito.pcap", normalni + napad)
print("Generisan meovito.pcap sa jasnom razlikom!")