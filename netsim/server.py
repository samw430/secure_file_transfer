import os, sys, getopt, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util import Counter, Padding
from Crypto import Random
import os

#params: statefile string
#return value: keys and sequence numbers from state file
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

#params: msg as bytes object
#return value: boolean whether session is initiated
def initiate_session(msg):

	# parse the message
	header = msg[:6]                    # header is 6 bytes long
	nonce = msg[6:14]      # nonce is AES.block_size/2 bytes long
	modulus = int.from_bytes(msg[14:2062], byteorder='big')
	encrypted_e = msg[2062:-32]
	header_from = header[:1]         # from is encoded on 1 byte
	header_type = header[1:2]           # type is encoded on 1 byte
	header_sqn = header[2:6]            # msg sqn is encoded on 4 bytes
	rcvmac = msg[-32:]

	#Check that this is login message
	if header_type != 0x00 and header_sqn != bytes(4):
		print("Invalid login from", header_from)
		return False

	#Get PBKDF2 key
	pass_file = open("./server_data/" + header_from.decode('utf-8') + "/password_derived_hash.txt", 'rb')
	pass_key = pass_file.read()
	pass_file.close()

	#initialize mac and update with msg
	MAC = HMAC.new(pass_key, digestmod=SHA256)
	MAC.update(msg[:-32])
	mac = MAC.digest()

	#check if potential attack occurred
	if mac != rcvmac:
		return False

	#initiliaze new cipher
	ctr = Counter.new(64, prefix=nonce, initial_value=0)
	cipher_aes = AES.new(pass_key, AES.MODE_CTR, counter = ctr)

	#decrypt exponent
	plaintext_e = cipher_aes.decrypt(encrypted_e)
	exponent = int.from_bytes(plaintext_e, byteorder = 'big')

	#Correct exponent if we randomly added 1 to it
	if exponent%2 ==0:
		exponent = exponent-1

	#make RSA cipher from modulus and exp as ints
	rsa = RSA.construct((modulus, exponent))

	#make and encrypt symmetric key for session
	symettric_key = Random.get_random_bytes(32)

	cipher = PKCS1_OAEP.new(rsa)
	encrypted_key = cipher.encrypt(symettric_key)

	zero = 0

	#build packet
	packet = OWN_ADDR.encode('utf-8') + zero.to_bytes(1, byteorder='big') + zero.to_bytes(4, byteorder='big') + encrypted_key

	#always use protection
	MAC = HMAC.new(pass_key, digestmod=SHA256)
	MAC.update(packet)
	mac = MAC.digest()

	netif.send_msg(header_from.decode('utf-8'), packet+mac)

	#update state file
	statefile = "./server_data/" + header_from.decode('utf-8') + "/state.txt"

	enckey = symettric_key[:16]
	mackey = symettric_key[16:]
	sndsqn = 0
	rcvsqn = 0
	#Save our new state
	state = "enckey: " + enckey.hex() + '\n'
	state = state + "mackey: " + mackey.hex() + '\n'
	state = state + "sndsqn: " + str(sndsqn + 1) + '\n'
	state = state + "rcvsqn: " + str(rcvsqn + 1)
	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

	print("Session initiated with " + header_from.decode('utf-8'))

	return True

#params: filename as string, statefile as string, client_name as bytes object
#return value: Pcket to send to client indicating they tried to download nonexistant file
def download_error(filename, statefile, client_name):
	tempfile = "./server_data/" + client_name + "/files/errorTemp"
	ofile = open(tempfile, "wb+")
	errorString = "The file " + filename[22:] + " does not exist"
	ofile.write(errorString.encode('utf-8'))
	ofile.close()
	packet = encrypt(tempfile, 6, statefile, client_name)
	os.remove(tempfile)	

	return packet

#params: filename as string, command as int, statefile as string, client_name as bytes
#return value: encrypted message to send to client
def encrypt(filename, command, statefile, client_name):

	# read the content of the state file
	enckey, mackey, sndsqn, rcvsqn = read_state_file(statefile)

	# read the content of the input file into payload
	filename = filename.rstrip()
	try:
		ifile = open(filename, 'rb')
	except FileNotFoundError:
		return download_error(filename, statefile, client_name)
	payload = ifile.read()
	ifile.close()

	#remove server metadata (removes path from filename)
	if command == 3:
		filename = filename[22:]

	#builds header
	server_address = "A"
	header_from = server_address.encode('utf-8')
	header_type = command.to_bytes(1,byteorder='big')
	header_sqn = (sndsqn + 1).to_bytes(4, byteorder='big')
	header = header_from+header_type+ header_sqn

	#filename will be first 50 bytes of encrypted
	filename = filename.ljust(50).encode('utf-8')

	#make new cipher to encrypt message
	iv = Random.get_random_bytes(AES.block_size)
	cipher = AES.new(enckey, AES.MODE_CBC, iv)
	
	encrypted = cipher.encrypt(Padding.pad(filename+payload,AES.block_size))

	#for #protection
	MAC = HMAC.new(mackey, digestmod=SHA256)
	MAC.update(header)
	MAC.update(iv)
	MAC.update(encrypted)
	mac = MAC.digest()

	message = header + iv + encrypted + mac

	#save state
	state = "enckey: " + enckey.hex() + '\n'
	state = state + "mackey: " + mackey.hex() + '\n'
	state = state + "sndsqn: " + str(sndsqn+1) + '\n'
	state = state + "rcvsqn: " + str(rcvsqn)

	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

	return message

#params: msg as bytes, netif as network object
#return value: boolean for session validity
def decrypt(msg, netif):

	# parse the message
	header = msg[:6]                    # header is 6 bytes long
	iv = msg[6:22]      # iv is AES.block_size bytes long
	encrypted = msg[22:-32] # encypted part
	mac = msg[-32:]
	header_from = header[:1]         # from is encoded on 1 byte
	header_type = header[1:2]           # type is encoded on 1 byte
	header_sqn = header[2:6]            # msg sqn is encoded on 4 bytes

	# read the content of the state file
	statefile = "./server_data/" + header_from.decode('utf-8') + "/state.txt"
	enckey, mackey, sndsqn, rcvsqn = read_state_file(statefile)


	# check the sequence number
	header_sqn = int.from_bytes(header_sqn, byteorder='big')
	if (rcvsqn >= header_sqn):
		#This is a sign of a replay attack
		print("Possible replay attack on " + header_from.decode("utf-8"))
		return False

	#verify mac
	MAC = HMAC.new(mackey,digestmod=SHA256)
	MAC.update(header)
	MAC.update(iv)
	MAC.update(encrypted)
	comp_mac = MAC.digest()

	if(comp_mac !=mac):
		#This is a sign of tampering
		return False

	ENC = AES.new(enckey, AES.MODE_CBC, iv)
	decrypted = ENC.decrypt(encrypted)

	#remove and check padding
	if len(decrypted)>0:
		try:
			decrypted = Padding.unpad(decrypted,AES.block_size)
		except ValueError:
			#connection invalid
			return False

	#list files
	if header_type == b'\x01':
		#os call to get files
		files = os.listdir("./server_data/" + header_from.decode('utf-8') + "/files/")
		#parse files into string
		fileString = ""
		for file in files:
			fileString = fileString + str(file) + '\n'
		#make and send from temp file
		tempfile = "./server_data/" + header_from.decode('utf-8') + "/files/lsTemp"
		ofile = open(tempfile, "wb+")
		ofile.write(fileString.encode('utf-8'))
		ofile.close()
		packet = encrypt(tempfile, 1, statefile, "")
		#must increment sndsqn because otherwise it doesn't increment for encryption
		sndsqn = sndsqn + 1
		netif.send_msg(header_from.decode('utf-8'), packet)
		#clean up temp file
		os.remove(tempfile)
		print(header_from.decode('utf-8'), "listed files")

	#upload
	elif header_type == b'\x02':
		filename = decrypted[:50]		#filename is first 50 bytes
		payload = decrypted[50:]

		#write file to server storage
		file = open("./server_data/" + header_from.decode('utf-8') + "/files/" + filename.decode('utf-8').rstrip(), "wb+")
		file.write(payload)
		file.close()
		print(header_from.decode('utf-8'), "uploaded", filename.decode('utf-8'))
	#download
	elif header_type == b'\x03':
		filename = decrypted[:50]
		filename = './server_data/' + header_from.decode('utf-8') + '/files/' + filename.decode('utf-8').rstrip()
		#get file contents and encrypt
		packet = encrypt(filename, 3, statefile, header_from.decode('utf-8'))
		#must increment sndsqn to account for encryption
		sndsqn = sndsqn + 1
		netif.send_msg(header_from.decode('utf-8'), packet)
		print(header_from.decode('utf-8'), "requested", filename)
	#remove file
	elif header_type == b'\x04':
		filename = decrypted[:50]		#filename is first 50 bytes
		#if requested file exists, remove it
		try:
			os.remove("./server_data/" + header_from.decode('utf-8') + "/files/" + filename.decode('utf-8').rstrip())
			print(header_from.decode('utf-8'), "deleted", filename.decode('utf-8'))
		except:
			print("User",header_from.decode('utf-8'),"tried to delete a file that doesn't exist")
	#logout
	elif header_type == b'\x05':
		#update password hash to match client
		new_hash = decrypted
		hash_file = open("./server_data/" + header_from.decode('utf-8') + "/password_derived_hash.txt", 'wb')
		hash_file.truncate()
		hash_file.write(new_hash)
		hash_file.close()
		print("User " + header_from.decode('utf-8') + " has logged out")
		return False

	# save state
	state = "enckey: " + enckey.hex() + '\n'
	state = state + "mackey: " + mackey.hex() + '\n'
	state = state + "sndsqn: " + str(sndsqn) + '\n'
	state = state + "rcvsqn: " + str(rcvsqn+1)
	ofile = open(statefile, 'wt')
	ofile.write(state)
	ofile.close()

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

#stores dictionary of client name to boolean representing connection validity
session_info = {}

print('Server running...')
while True:

	status, msg = netif.receive_msg(blocking=True)
	user_id = msg[:1]

	if user_id in session_info and session_info[user_id]:
		#handle requests here
		session_info[user_id] = decrypt(msg, netif)
	else:
		session_info[user_id] = initiate_session(msg)
