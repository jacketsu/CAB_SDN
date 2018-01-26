# download repo
    git clone http://github.com/bovenyan/CAB_SDN
    git checkout cython

# compile libcab.so:
    cd $REPO_HOME
    mkdir build
    cd build
    cmake ../
    make
    # there should be a shared lib

# compile pyCABcython.so
    export $LD_LIBRARY_PATH=$REPO_HOME/cython 
    python setup.py build_ext --inplace
    python test.py 

# TODO List:
    write a python wrap up to extend pyCABcython.pyx
        feature 1: ovs-vsctl, ovs-ofctl syntax to wrap bucket gen and load rule functionality
        feature 2: Refer to test.py, call CAB-cython APIs to search bucket/rules in the thrift client.
    
    comprehensive debugging:
        compare to original CAB stack, all the boosts functions are stripped, pls verify correctness
        CABcython.* are added logic, verify correctness.
        run real traffic/rule to test.
