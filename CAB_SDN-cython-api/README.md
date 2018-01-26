# Compile CAB Program at CAB_SDN folder
mkdir build
cd build
cmake ../
cd ../bin

# Run CABDaemon
./CABDaemon rulefile 

# Run ryu-controller
cd ../controller
ryu-manager cab_switch_cab_v6 ../config/ryu_config.ini

# Install client echoer module @ client machine
### this ensures that every packet sent to the client will be pump back.
cd ../trace_gen
make
lsmod | grep cecho
sudo rmmod cecho
sudo insmod ./client_echo.ko
lsmod | grep cecho

# Usecase test cast checklist
### prepare 
0. compile all the tools 
    mkdir build 
    cd build
    cmake ../
    make

1. get firewall rules and ipc rules
    @ metadata/ruleset
    verify that the ruleset has a default full cover rule

2. run trace generator to generate traces
    @ bin
    ./TracePrepare -c ../config/TracePrepare_config.ini -r ../metadata/ruleset/acl2k.rules

### monitoring
3. run dump_collect.sh at both hosts
    @ trace_gen
    ./dump_collect.sh p3p1         or p7p3

### run test
4. run CAB_DAEMON & ryu_controller
    @ bin @bigmac01
    ./CABDaemon ../config/CABDaemon_config.ini ../metadata/ruleset/acl2k.rules
    make sure to use the same rule set

5. run FlowEcho 
    @ bin @bigmac02
    ./FlowEcho -i p7p3 --ipv4

6. run traffic generator (remember sudo)
    @ bin @bigmac01
    sudo ./FlowGen -s blah.stats -i p3p1 -f Trace_Generate/trace-100k-0.01-20/GENtrace/ref_trace.gz --ipv4

### collect stats
6. calculate and plot latency figure.
    move monitor file from bigmac01 and bigmac02 in step 3. 
    ./CalTrace  -s bigmac01.file -r bigmac02.file
    gnuplot ....

### cython programming:
7. Cython architecture
    https://docs.google.com/presentation/d/1Ftlk1Brdrdo3kViP4HARJeyc6mb8B30_nAbSSRnc7iM/edit?usp=sharing 
