import os, sys, getopt, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter
from Crypto import Random

def initiate_session(msg):
	user_id = msg[:1]
	nonce = msg[1:9]
	encrypted_e = msg[2057:]
	modulus = int.from_bytes(msg[9:2057], byteorder='big')

	#Get PBKDF2 key
	pass_file = open("./server_data/" + user_id.decode('utf-8') + "/password_derived_hash.txt", 'rb')
	pass_key = pass_file.read()
	pass_file.close()

	ctr = Counter.new(64, prefix=nonce, initial_value=0)
	cipher_aes = AES.new(pass_key, AES.MODE_CTR, counter = ctr)

	plaintext_e = cipher_aes.decrypt(encrypted_e)
	exponent = int.from_bytes(plaintext_e, byteorder = 'big')

	if exponent%2 ==0:
		exponent = exponent-1

	rsa = RSA.construct((modulus, exponent))

	symettric_key = Random.get_random_bytes(16)

	cipher = PKCS1_OAEP.new(rsa)
	encrypted_key = cipher.encrypt(symettric_key)

	netif.send_msg('B', encrypted_key)

	print("Session initiated with " + user_id.decode('utf-8') + " with key:")
	print(symettric_key)

	return (True, symettric_key)

def handle_request(msg):
	header = msg[:7].decode('utf-8')

	if header[1:] == "logout":
		hash_file = open("./server_data/" + header[:1] + "/password_derived_hash.txt", 'wb')
		hash_file.truncate()
		hash_file.write(msg[7:])
		hash_file.close()
		return True


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

session_info = {}

print('Server running...')
while True:

	status, msg = netif.receive_msg(blocking=True)
	user_id = msg[:1]

	if user_id in session_info and session_info[user_id][0]:
		#handle requests here
		if handle_request(msg):
			print("User " + user_id.decode('utf-8') + " logged out")
			session_info[user_id] = (False, b'0')
	else:
		session_info[user_id] = initiate_session(msg)

