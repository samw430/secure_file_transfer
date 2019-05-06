import os, sys, getopt, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter, Padding
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

def get_salt(address):
	salt_doc = open("./client_data/" + address + "/salt.txt", 'rb')
	return salt_doc.read()

def update_salt(address, password):
	salt = Random.get_random_bytes(16)

	saltDoc = open('./client_data/' + address + '/salt.txt', 'wb')
	saltDoc.write(salt)

	pass_based_key = PBKDF2(password, salt, 16, 1000)

	#This needs to be encrypted once that function is written
	packet = address.encode('utf-8') + "logout".encode('utf-8') + pass_based_key
	return packet

def encrypt(filename, command):

	# read the content of the state file
	ifile = open(sndfile, 'rt')
	line = ifile.readline()
	enckey = line[len("enckey: "):len("enckey: ")+32]
	enckey = bytes.fromhex(enckey)
	line = ifile.readline()
	mackey = line[len("mackey: "):len("mackey: ")+32]
	mackey = bytes.fromhex(mackey)
	line = ifile.readline()
	sndsqn = line[len("sndsqn: "):]
	sndsqn = int(sndsqn, base=10)
	ifile.close()

	# read the content of the input file into payload
	ifile = open(filename, 'rb')
	payload = ifile.read()
	ifile.close()

	header_from = OWN_ADDR.encode('utf-8').to_bytes(1,byteorder='big')
	header_type = command.to_bytes(1,byteorder='big')
	header_sqn = (sndsqn + 1).to_bytes(4, byteorder='big')
	header = header_from+header_type+ header_sqn

	#filename will be first 50 bytes of encrypted
	filename = filename.to_bytes(50,byteorder='big')

	iv = Random.get_random_bytes(AES.block_size)
	cipher = AES.new(enckey, AES.MODE_CBC, iv)
	#might be problem because filename is bytes
	#maybe use:
	#str(int.from_bytes(filename, byteorder='big'))
	encrypted = ENC.encrypt(pad(filename+payload,AES.block_size))

	MAC = HMAC.new(mackey, digestmod=SHA256)
	MAC.update(header)
	MAC.update(iv)
	MAC.update(encrypted)
	mac = MAC.digest()

	message = header + iv +  encrypted + mac

	# save state
	state = "enckey: " + enckey.hex() + '\n'
	state = state + "mackey: " + mackey.hex() + '\n'
	state = state + "sndsqn: " + str(sndsqn + 1)
	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

	return message

def decrypt(msg):

	# parse the message
	header = msg[:6]                    # header is 6 bytes long
	iv = msg[6:(AES.block_size)+6]      # iv is AES.block_size bytes long
	encrypted = msg[(AES.block_size)+6:-32] # encypted part
	mac = msg[-32:]
	header_from = header[:1]         # from is encoded on 1 byte
	header_type = header[1:2]           # type is encoded on 1 byte
	header_sqn = header[2:6]            # msg sqn is encoded on 4 bytes

	# read the content of the receive state file
	recfile = header_from#need to encode this based on from
	ifile = open(recfile, 'rt')
	line = ifile.readline()
	enckey = line[len("enckey: "):len("enckey: ")+32]
	enckey = bytes.fromhex(enckey)
	line = ifile.readline()
	mackey = line[len("mackey: "):len("mackey: ")+32]
	mackey = bytes.fromhex(mackey)
	line = ifile.readline()
	rcvsqn = line[len("rcvsqn: "):]
	rcvsqn = int(rcvsqn, base=10)
	ifile.close()

	# check the sequence number
	sndsqn = int.from_bytes(header_sqn, byteorder='big')
	if (sndsqn < (rcvsqn +1)):
		#need to decide what we do here
		#sys.exit(1)
		terminate()

	#verify mac
	MAC = HMAC.new(mackey,digestmod=SHA256)
	MAC.update(header)
	MAC.update(iv)
	MAC.update(encrypted)
	comp_mac = MAC.digest()

	if(comp_mac !=mac):
		#do something here
		#sys.exit(1)

	ENC = AES.new(enckey, AES.MODE_CBC, iv)
	decrypted = ENC.decrypt(encrypted)

	#remove and check padding
	try:
		decrypted = unpad(decrypted,AES.block_size)
	except ValueError:
		#need to decide what we do here
		terminate()

	filename = decrypted[:50]		#filename is first 50 bytes
	payload = decrypted[50:]

	# save state
	state = "enckey: " + enckey.hex() + '\n'
	state = state + "mackey: " + mackey.hex() + '\n'
	state = state + "rcvsqn: " + str(sndsqn)
	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

	#do something based on the type of message


NET_PATH = './network/'
OWN_ADDR = 'B'
PASSWORD = ""

# ------------
# main program
# ------------

#Get and set arguments
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
salt = get_salt(OWN_ADDR)
pass_based_key = PBKDF2(PASSWORD, salt, 16, 1000)

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

cipher_aes = AES.new(pass_based_key, AES.MODE_CTR, counter = ctr)

ciphertext = cipher_aes.encrypt(exponent.to_bytes(66000, byteorder='big'))

header_from = OWN_ADDR.encode('utf-8').to_bytes(1, )
#need to decie on header type codes
header_type = 0.to_bytes(1,byteorder='big')
#first message should be zero?
header_sqn = 0.to_bytes(4, byteorder='big')
header = header_from+header_type+ header_sqn

packet = header + cipher_aes.nonce + modulus.to_bytes(2048, byteorder='big') + ciphertext
#old way
#packet = OWN_ADDR.encode('utf-8') + cipher_aes.nonce + modulus.to_bytes(2048, byteorder='big') + ciphertext

print(len(modulus.to_bytes(2048, byteorder='big')))

netif.send_msg('A', packet)

status, msg = netif.receive_msg(blocking=True)

cipher_rsa = PKCS1_OAEP.new(key)
session_key = cipher_rsa.decrypt(msg)

print('Session established with server...')

while True:

	command = input("Enter a command:")

	if command == "help" or command == "h":
		print("ls              ... Lists remote files")
		print("up <filename>   ... Uploads filename to remote server")
		print("down <filename> ... Downloads filenmae from remote server")
		print("rm <filename>   ... Deletes filename from remote server")
		print("logout          ... Logs out from remote server")
	elif command == "logout":
		packet = update_salt(OWN_ADDR, PASSWORD)
		netif.send_msg('A', packet)
		print("Logging out...")
		break
#while True:
# Calling receive_msg() in non-blocking mode ...
#	status, msg = netif.receive_msg(blocking=False)
#	if status: print(msg)      # if status is True, then a message was returned in msg
#	else: time.sleep(2)        # otherwise msg is empty

# Calling receive_msg() in blocking mode ...


#	status, msg = netif.receive_msg(blocking=True)      # when returns, status is True and msg contains a message
#	print(msg.decode('utf-8'))
