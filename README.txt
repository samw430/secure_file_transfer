Must run network.py first 

python3 network.py -p './network/' -a 'ABCDE' --clean
python3 sender.py -p './network/' -a A
python3 receiver.py -p './network/' -a B