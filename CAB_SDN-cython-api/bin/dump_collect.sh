# usage  ./dump_collect.sh p7p3

sudo tcpdump -i $1 -w dump-$1.pcap 
