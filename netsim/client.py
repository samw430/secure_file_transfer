import os, sys, getopt, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter
from Crypto import Random
import struct

NET_PATH = './network/'
OWN_ADDR = 'B'
PASSWORD = ""

# ------------       
# main program
# ------------

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:l:', longopts=['help', 'path=', 'addr=', 'pass='])
except getopt.GetoptError:
	print('Usage: python receiver.py -p <network path> -a <own addr> -l <password>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python receiver.py -p <network path> -a <own addr> -l <password>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg
	elif opt == '-l' or opt == '--pass':
		PASSWORD = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)


#Initialize network 
netif = network_interface(NET_PATH, OWN_ADDR)

#Password based key exchange protocol
h = SHA256.new()
h.update('hello'.encode('utf-8'))
hashed_pass = h.digest()

print(hashed_pass)

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

pubkey = RSA.importKey(public_key)

modulus = pubkey.n
exponent = pubkey.e

random_num = int.from_bytes(Random.get_random_bytes(1), byteorder = 'big')
if random_num < 128:
	exponent = exponent+1

nonce = Random.get_random_bytes(8)
ctr = Counter.new(64, prefix=nonce, initial_value=0)

cipher_aes = AES.new(hashed_pass, AES.MODE_CTR, counter = ctr)

print(exponent)

ciphertext = cipher_aes.encrypt(exponent.to_bytes(66000, byteorder='big'))

cipher_aes2 = AES.new(hashed_pass, AES.MODE_CTR, counter = ctr)

packet1 = cipher_aes.nonce + ciphertext
packet2 = modulus.to_bytes(2048, byteorder='big')

netif.send_msg('A', packet1)
netif.send_msg('A', packet2)

status, msg = netif.receive_msg(blocking=True)

cipher_rsa = PKCS1_OAEP.new(key)
session_key = cipher_rsa.decrypt(msg)
print(session_key)




print('Main loop started...')
#while True:
# Calling receive_msg() in non-blocking mode ... 
#	status, msg = netif.receive_msg(blocking=False)    
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...
	

#	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message 
#	print(msg.decode('utf-8'))