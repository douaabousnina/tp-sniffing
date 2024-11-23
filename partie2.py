from scapy.all import sniff, Dot11

def parse(frame):
    if frame.haslayer(Dot11):
        print("ToDS:", frame.FCfield & 0b1 != 0)  
        print("MF:", frame.FCfield & 0b10 != 0)  # 2ème bit => MF bit (fragmenté ou non)
        print("WEP:", frame.FCfield & 0b01000000 != 0)  
        print("src MAC:", frame.addr2)  
        print("dest MAC:", frame.addr1)  
        print("BSSID:", frame.addr3)  
        print("Duration ID:", frame.ID)  
        print("Sequence Control:", frame.SC)  
        # print(feature(frame))  
        print("\n")  

sniff(offline="C:/Users/user/Desktop/Wireshark_802_11.pcap", prn=parse)
