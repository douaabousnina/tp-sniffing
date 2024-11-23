from scapy.all import sniff, Dot11, Dot11Elt
from collections import defaultdict

def count_association_requests_by_ap(pcap_file):
    try:
        ap_info = {}
        association_counts = defaultdict(int)

        def parse(packet):
            if packet.haslayer(Dot11):
                
                # Extraction du SSID & BSSID à partir de Beacon / Probe response
                if packet.type == 0 and packet.subtype in [8, 5]:
                    bssid = packet.addr2 
                    ssid = packet[Dot11Elt].info.decode(errors="ignore") if packet.haslayer(Dot11Elt) else "<Unknown>"
                    ap_info[bssid] = ssid

                # Compter les tentatives d'association
                if packet.type == 0 and packet.subtype == 0:
                    bssid = packet.addr3
                    if bssid:
                        association_counts[bssid] += 1

        sniff(offline=pcap_file, prn=parse)

        results = []
        for bssid, count in association_counts.items():
            ssid = ap_info.get(bssid, "<SSID inconnu>")
            results.append((ssid, bssid, count))
        
        return results

    except FileNotFoundError:
        print(f"Le fichier {pcap_file} est introuvable.")
        return None

if __name__ == "__main__":
    pcap_path = "C:/Users/user/Desktop/Wireshark_802_11.pcap"
    ap_association_data = count_association_requests_by_ap(pcap_path)
    if ap_association_data:
        print("Nombre de tentatives d'association par point d'accès :")
        for ssid, bssid, count in ap_association_data:
            print(f"* Point d'accès: {ssid} (BSSID: {bssid}) \n\tTentatives: {count}")
    else:
        print("Erreur lors de l'analyse.")
