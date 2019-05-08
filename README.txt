Must run network.py first 

python3 network.py -p './network/' -a 'ABCDE' --clean
python3 sender.py -p './network/' -a A
python3 receiver.py -p './network/' -a B

To Do

check if file is of length <= 50
put message numbers on server decrypt in order
if request file that doesn't exist, need to send message to client