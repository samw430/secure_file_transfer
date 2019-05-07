from Crypto import Random

salt = Random.get_random_bytes(16)

saltDoc = open('./client_data/C/salt.txt', 'wb')
saltDoc.write(salt)
