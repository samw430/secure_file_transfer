Must run network.py first 

python3 network.py -p './network/' -a 'ABCDE' --clean
python3 server.py
python3 client.py -l hello
python3 client.py -a C -l hello

To make a new user:
Initialize user's salt with salt_generator.py
Uncomment line for initializing server_data in client code
Login once
Comment back out line for initializing server_data in client code
