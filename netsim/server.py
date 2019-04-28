import os, sys, getopt, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter
from Crypto import Random

NET_PATH = './network/'
OWN_ADDR = 'A'

try:
	opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
	print('Usage: python sender.py -p <network path> -a <own addr>')
	sys.exit(1)

for opt, arg in opts:
	if opt == '-h' or opt == '--help':
		print('Usage: python sender.py -p <network path> -a <own addr>')
		sys.exit(0)
	elif opt == '-p' or opt == '--path':
		NET_PATH = arg
	elif opt == '-a' or opt == '--addr':
		OWN_ADDR = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
	print('Error: Cannot access path ' + NET_PATH)
	sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
	print('Error: Invalid address ' + OWN_ADDR)
	sys.exit(1)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)
print('Main loop started...')
while True:

	status1, msg1 = netif.receive_msg(blocking=True)
	status2, msg2 = netif.receive_msg(blocking=True)

	nonce = msg1[:8]
	encrypted_e = msg1[8:]

	print(encrypted_e)

	h = SHA256.new()
	h.update("hello".encode('utf-8'))
	hashed_pass = h.digest()


	ctr = Counter.new(64, prefix=nonce, initial_value=0)
	print(hashed_pass)
	cipher_aes = AES.new(hashed_pass, AES.MODE_CTR, counter = ctr)

	plaintext_e = cipher_aes.decrypt(encrypted_e)
	print("is me")
	#print(plaintext_e)
	exponent = int.from_bytes(plaintext_e, byteorder = 'big')

	if exponent%2 ==0:
		exponent = exponent-1

	modulus = int.from_bytes(msg2, byteorder='big')

	print(exponent)
	rsa = RSA.construct((modulus, exponent))

	symettric_key = Random.get_random_bytes(16)

	cipher = PKCS1_OAEP.new(rsa)
	encrypted_key = cipher.encrypt(symettric_key)

	print(symettric_key)

	netif.send_msg('B', encrypted_key)





#	msg = input('Type a message: ')
#	dst = input('Type a destination address: ')

#	netif.send_msg(dst, msg.encode('utf-8'))

#	if input('Continue? (y/n): ') == 'n': break