#ifndef CAB_CYTHON_H
#define CAB_CYTHON_H

#include <string>
#include <vector>

using std::string;
using std::vector;

class CABcython{
public:
    CABcython();
    CABcython(string rule_file, int thres_hard);

    // Input: 4 tuple sIP, dIP, sPort, dPort as input, check .pyx interface
    // Return: concatenated 8 tuples.
    // bucket (sIP prefix, sIP mask, dIP...) 8 tuple
    // rule1  (sIP prefix, sIP mask, dIP...) 8 tuple
    // rule2  (sIP prefix, sIP mask ...)
    // rule3 ... 
    vector<unsigned long> queryBTree(vector<unsigned long> pktQuery); 
    ~CABcython();
};

#endif
