from scapy.all import *
from scapy.arch.windows import get_windows_if_list
from .detection import analyze_traffic
import time
from pprint import pprint


conf.verb = 0 # Disable verbose mode

packets = []

def parse_packet(packet):
  """Sniff callback function
  """
  if packet: 
    if packet.haslayer('UDP'):
      udp = packet.getlayer('UDP')
      packets.append(udp)
      udp.show()
    else:
      packets.append(
        {
          "time": time.time(),
          "src": packet[0].src,
          "dst": packet[0].dst
        }
      )
      print(analyze_traffic())
      print(f"Packet: {packet[0].src} -> {packet[0].dst}")
  else:
    print("No packet found, try again with a network connection")
    
    
def packet_sniffer():
  """Start a sniffer
  """
  interfaces = get_windows_if_list()
  pprint(interfaces) # A simple get interface for wifi will be created for use later on, incase of differing interfaces lists
  print('\n[*] Start udp/packet sniffer')
  sniff(
    iface=interfaces[4]["name"],
    prn=parse_packet,
    store=0,
    count=100 # We are sending 100 packets for testing.
  )
  
def load_pcap(file_path):
  global packets
  packets = [
    {
      "time": i,
      "src": p[0].src,
      "dst": p[0].dst
    }
    for i, p in enumerate(rdpcap(file_path))
  ]
  print(f"Loaded {len(packets)} packets from {file_path}")
  
# def packet_callback(packet):
#     packets.append({"time": time.time(), "src": packet[0].src, "dst": packet[0].dst})
#     print(f"Packet: {packet[0].src} -> {packet[0].dst}")

# def start_sniffing(interface="WiFi"):
#     print("Available interfaces:", get_if_list())
#     sniff(iface=interface, prn=packet_callback, store=0, count=100)  # 100 packets for testing