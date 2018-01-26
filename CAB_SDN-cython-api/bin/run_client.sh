# run echo
./FlowEcho -i p7p3 --ipv4 &

# run collector
./dump_collect.sh p7p3 &

# validate 
sudo ps aux | grep FlowEcho
sudo ps aux | grep tcpdump 
