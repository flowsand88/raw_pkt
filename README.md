raw packet send or recv tool.

compile:
gcc -o raw_pkt raw_pkt.c

usage:
./raw_pkt --send -i ethX [-c xx] [-t xx | -s xx]
./raw_pkt --recv -i ethX 

