from netinterface import network_interface
import os

NET_PATH = './network/'

netif = network_interface(NET_PATH, 'B')


files = os.listdir("./network/B/OUT/")
sortedFiles = sorted(files)
print(sortedFiles)

filename = sortedFiles[len(sortedFiles)-1]
packet = open("./network/B/OUT/" + filename, 'rb').read()

netif.send_msg('A', packet)
print("Malicious Packet Sent")