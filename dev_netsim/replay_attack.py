from netinterface import network_interface
import os

NET_PATH = './network/'

netif = network_interface(NET_PATH, 'B')

packetString = open("replay.txt", 'r').read().replace(" ", "").replace("\n","")
print(packetString)
packet = bytes.fromhex(packetString)

netif.send_msg('A', packet)
print("Malicious Packet Sent")