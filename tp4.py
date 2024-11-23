import argparse
import os
import sys
from scapy.utils import RawPcapReader
from scapy.layers.dot11 import Dot11
from scapy.all import PcapReader



def process_pcap(file_name):
    print(f'Opening {file_name}...')
    
    try:
        for dot11_packet in PcapReader(file_name):
            try:
                if (dot11_packet.haslayer(Dot11)):
                    print(dot11_packet)
                else:
                    print("Packet skipped: This is not a wifi (802.11) packet.")
            except Exception as e:
                print(f"Error processing packet: {e}", file=sys.stderr)
            
            
    except FileNotFoundError:
        print(f"File {file_name} not found!", file=sys.stderr)
        sys.exit(-1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>',
                        help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print(f'"{file_name}" does not exist', file=sys.stderr)
        sys.exit(-1)

    process_pcap(file_name)
    sys.exit(0)
