from libcpp.vector cimport vector
from libcpp.string cimport string

cdef extern from "CABcython.h":
    cdef cppclass CABcython:
        CABcython() except +
        CABcython(string, int) except +
        vector[unsigned long] queryBTree(vector[unsigned long] pktQuery) except +

cdef class pyCABcython:
    cdef CABcython * c_cab

    def __cinit__(self, string rule_file, int thres_hard):
        print "before creating..."
        self.c_cab = new CABcython(rule_file, thres_hard)
        print "after creating"

    def __dealloc__(self):
        del self.c_cab


    # Input: 4 tuple sIP, dIP, sPort, dPort as input, check .pyx interface
    # Return: concatenated 8 tuples.
    # bucket (sIP prefix, sIP mask, dIP...) 8 tuple
    # rule1  (sIP prefix, sIP mask, dIP...) 8 tuple
    # rule2  (sIP prefix, sIP mask ...)
    # rule3 ... 
    def query_btree(self, sIP, dIP, sPort, dPort):
        print sIP, dIP, sPort, dPort
        cdef vector[unsigned long] query
        query.push_back(sIP)
        query.push_back(dIP)
        query.push_back(sPort)
        query.push_back(dPort)
        res = self.c_cab.queryBTree(query)
        N = res.size()
        resPy = []
        for i in range(N):
            resPy.append(res[i])
        return resPy
