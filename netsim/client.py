import os, sys, getopt, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter, Padding
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2

"""
Action Codes:
Login   0
ls      1
up      2
down    3
rm      4
logout  5 
error   6

Passwords:
B hello
C crypt
"""

#params: address is user name as string
#return val: stored salt value
def get_salt(address):
	salt_doc = open("./client_data/" + address + "/salt.txt", 'rb')
	return salt_doc.read()

#params: address is user name as string, password
#return val: key based on password and salt with side effect of modifying salt file
def update_salt(address, password):
	salt = Random.get_random_bytes(16)

	saltDoc = open('./client_data/' + address + '/salt.txt', 'wb')
	saltDoc.write(salt)

	return PBKDF2(password, salt, 16, 1000)

#params: statefile string
#return val: keys and sequence numbers from state file
def read_state_file(statefile):

	# read the content of the state file
	ifile = open(statefile, 'rt')
	line = ifile.readline()
	enckey = line[len("enckey: "):len("enckey: ")+32]
	enckey = bytes.fromhex(enckey)
	line = ifile.readline()
	mackey = line[len("mackey: "):len("mackey: ")+32]
	mackey = bytes.fromhex(mackey)
	line = ifile.readline()
	sndsqn = line[len("sndsqn: "):]
	sndsqn = int(sndsqn, base=10)
	line = ifile.readline()
	rcvsqn = line[len("rcvsqn: "):]
	rcvsqn = int(rcvsqn, base=10)
	ifile.close()

	return (enckey, mackey, sndsqn, rcvsqn)

#params: filename as string, command as int, statefile as string, password as string
#return val: Tuple(boolean whether to send message, message as bytes if necessary)
def encrypt(filename, command, statefile, password):

	enckey, mackey, sndsqn, rcvsqn = read_state_file(statefile)

	#Build header for packet
	header_from = OWN_ADDR.encode('utf-8')
	header_type = command.to_bytes(1,byteorder='big')
	header_sqn = (sndsqn + 1).to_bytes(4, byteorder='big')
	header = header_from+header_type+ header_sqn

	#Create MAC object and include header
	MAC = HMAC.new(mackey, digestmod=SHA256)
	MAC.update(header)

	if len(filename) > 50:
		print("Filenames can be at most 50 characters")
		return (False,b'')

	encrypted = b''

	#Initialize encryption object for payload
	iv = Random.get_random_bytes(AES.block_size)
	cipher = AES.new(enckey, AES.MODE_CBC, iv)

	#List remote files
	if command == 1:
		#No file or payload required by server
		encrypted = b''
	#upload
	elif command == 2:
		# read the content of the input file into payload
		try:
			ifile = open(statefile[:-9] + filename, 'rb')
			payload = ifile.read()
			ifile.close()
		except:
			print("Filename doesn't exist locally")
			return (False, b'')

		#filename will be first 50 bytes of encrypted
		filename = filename.ljust(50).encode('utf-8')
		encrypted = cipher.encrypt(Padding.pad(filename+payload,AES.block_size))
	#download
	elif command == 3:
		#Download requires file name but no payload
		filename = filename.ljust(50).encode('utf-8')
		encrypted = cipher.encrypt(Padding.pad(filename,AES.block_size))
	#remove file
	elif command == 4:
		#filename will be first 50 bytes of encrypted
		filename = filename.ljust(50).encode('utf-8')	
		encrypted = cipher.encrypt(Padding.pad(filename,AES.block_size))
	#logout 
	elif command == 5:
		#Get new key for next session initiation 
		new_key = update_salt(OWN_ADDR, password)
		encrypted = cipher.encrypt(Padding.pad(new_key,AES.block_size)) 

	#Add rest of packet to MAC value
	MAC.update(iv)
	MAC.update(encrypted)
		
	#Digest MAC and form packet
	mac = MAC.digest()
	message = header + iv +  encrypted + mac

	# save state
	state = "enckey: " + enckey.hex() + '\n'
	state = state + "mackey: " + mackey.hex() + '\n'
	state = state + "sndsqn: " + str(sndsqn + 1) + '\n'
	state = state + "rcvsqn: " + str(rcvsqn)
	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

	return (True, message)

#params: msg as bytes, statefile as string
#return val: boolean with True as maintain session and false if potential attacks
def decrypt(msg, statefile):

	# parse the message
	header = msg[:6]                    # header is 6 bytes long
	iv = msg[6:(AES.block_size)+6]      # iv is AES.block_size bytes long
	encrypted = msg[(AES.block_size)+6:-32] # encypted part
	mac = msg[-32:]
	header_from = header[:1]         # from is encoded on 1 byte
	header_type = header[1:2]           # type is encoded on 1 byte
	header_sqn = header[2:6]            # msg sqn is encoded on 4 bytes

	# read the content of the receive state file
	enckey, mackey, sndsqn, rcvsqn = read_state_file(statefile)

	# check the sequence number
	headersqn = int.from_bytes(header_sqn, byteorder='big')
	if (rcvsqn > headersqn):
		print("Bad sequence number")
		return False

	#verify mac
	MAC = HMAC.new(mackey,digestmod=SHA256)
	MAC.update(header)
	MAC.update(iv)
	MAC.update(encrypted)
	comp_mac = MAC.digest()

	if(comp_mac !=mac):
		print("Bad MAC value")
		return False

	#Decrypt payload
	ENC = AES.new(enckey, AES.MODE_CBC, iv)
	decrypted = ENC.decrypt(encrypted)

	#remove and check padding
	try:
		decrypted = Padding.unpad(decrypted,AES.block_size)
	except ValueError:
		print("Bad padding")
		return False

	#Decrypt ls packet
	if header_type == b'\x01':
		print(decrypted[50:].decode('utf-8'))
	#decrypt download packet
	elif header_type == b'\x03':
		filename = decrypted[:50]		#filename is first 50 bytes
		payload = decrypted[50:]

		#make new file or possibly overwrite old file
		f = open("./client_data/" + OWN_ADDR + "/" + filename.decode('utf-8').rstrip(),"wb+")
		f.write(payload)
		f.close()
		print("File Download")
	#decrypt error message
	elif header_type == b'\x06':
		print(decrypted[50:].decode('utf-8'))

	# save state
	state = "enckey: " + enckey.hex() + '\n'
	state = state + "mackey: " + mackey.hex() + '\n'
	state = state + "sndsqn: " + str(sndsqn) + '\n'
	state = state + "rcvsqn: " + str(rcvsqn+1)
	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

	return True

#params: OWN_ADDR as string, netif as network interface, PASSWORD as string, statefile as string
#return val: null
#Side effect: Negotiate session and save session key in state file
def initialize_session(OWN_ADDR, netif, PASSWORD, statefile):
	#Password based key exchange protocol using EKE

	salt = get_salt(OWN_ADDR)
	pass_based_key = PBKDF2(PASSWORD, salt, 16, 1000)
	
	#In testing if passwords get out of sync between server and client
	#open("./server_data/" + OWN_ADDR + "/password_derived_hash.txt", 'wb').write(pass_based_key)

	#Generate RSA key 
	key = RSA.generate(2048)
	private_key = key.export_key()
	public_key = key.publickey().export_key()

	pubkey = RSA.importKey(public_key)

	#Get modulus and exponent from public key
	modulus = pubkey.n
	exponent = pubkey.e

	#Add 1 to exponent with probability 1/2
	random_num = int.from_bytes(Random.get_random_bytes(1), byteorder = 'big')
	if random_num < 128:
		exponent = exponent+1

	#Initialize encryption variables
	nonce = Random.get_random_bytes(8)
	ctr = Counter.new(64, prefix=nonce, initial_value=0)

	cipher_aes = AES.new(pass_based_key, AES.MODE_CTR, counter = ctr)

	#encrypt payload
	ciphertext = cipher_aes.encrypt(exponent.to_bytes(66000, byteorder='big'))

	#Build packet header
	header_from = OWN_ADDR.encode('utf-8')
	zero = 0
	header_type = zero.to_bytes(1,byteorder='big')
	#first message should be zero?
	header_sqn = zero.to_bytes(4, byteorder='big')
	header = header_from+header_type+ header_sqn

	packet = header + cipher_aes.nonce + modulus.to_bytes(2048, byteorder='big') + ciphertext
	
	#Generate MAC value for protection
	MAC = HMAC.new(pass_based_key, digestmod=SHA256)
	MAC.update(packet)
	mac = MAC.digest()

	packet = packet + mac

	netif.send_msg('A', packet)

	status, msg = netif.receive_msg(blocking=True)

	# parse the message
	header = msg[:6]                    # header is 6 bytes long
	encrypted_keys = msg[6:-32]
	header_from = header[:1]         # from is encoded on 1 byte
	header_type = header[1:2]           # type is encoded on 1 byte
	header_sqn = header[2:6]            # msg sqn is encoded on 4 bytes
	rcvmac = msg[-32:]

	#Check MAC value of recieved server message
	MAC = HMAC.new(pass_based_key, digestmod=SHA256)
	MAC.update(msg[:-32])
	mac = MAC.digest()
	if mac != rcvmac:
		print("Server compromised")
		return

	#Decrypt symmetric session keys with RSA private key
	cipher_rsa = PKCS1_OAEP.new(key)
	session_keys = cipher_rsa.decrypt(encrypted_keys)

	#Initialize state file
	sndsqn = 0
	rcvsqn = 0
	state = "enckey: " + session_keys[:16].hex() + '\n'
	state = state + "mackey: " + session_keys[16:].hex() + '\n'
	state = state + "sndsqn: " + str(sndsqn + 1) + '\n'
	state = state + "rcvsqn: " + str(rcvsqn + 1)
	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

	print('Session established with server...')


NET_PATH = './network/'
OWN_ADDR = 'B'
PASSWORD = ""
STATE_FILE = ""

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

STATE_FILE = "./client_data/" + OWN_ADDR + "/state.txt"


#Initialize network
netif = network_interface(NET_PATH, OWN_ADDR)

initialize_session(OWN_ADDR, netif, PASSWORD, STATE_FILE)

while True:

	command = input("Enter a command: ")

	#Act based on command
	if command == "help" or command == "h":
		print("ls              ... Lists remote files")
		print("up <filename>   ... Uploads filename to remote server")
		print("down <filename> ... Downloads filenmae from remote server")
		print("rm <filename>   ... Deletes filename from remote server")
		print("logout          ... Logs out from remote server")
	elif command == "logout":
		packet = encrypt("", 5, STATE_FILE, PASSWORD)
		if packet[0]:
			netif.send_msg('A', packet[1])
		print("Logging out...")
		break
	elif command[:3] == "up ":
		packet = encrypt(command[3:], 2, STATE_FILE, PASSWORD)
		if packet[0]:
			netif.send_msg('A', packet[1])
			print("File " + command[3:] + " uploaded")
	elif command[:5] == "down ":
		packet = encrypt(command[5:], 3, STATE_FILE, PASSWORD)
		if packet[0]:
			netif.send_msg('A', packet[1])
			print("Waiting for file...")
			status, msg = netif.receive_msg(blocking=True)
			decrypted = decrypt(msg, STATE_FILE)
	elif command == "ls":
		packet = encrypt("", 1, STATE_FILE, PASSWORD)
		if packet[0]:
			netif.send_msg('A', packet[1])
			print("Requesting list of remote files...")
			status, msg = netif.receive_msg(blocking=True)
			decrypt(msg, STATE_FILE)
	elif command[:3] == "rm ":
		packet = encrypt(command[3:], 4, STATE_FILE, PASSWORD)
		if packet[0]:
			netif.send_msg('A', packet[1])
			print("Attempting to remove file " + command[3:])