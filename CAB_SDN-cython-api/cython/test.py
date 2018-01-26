from pyCABcython import pyCABcython
import random

ca = pyCABcython("../metadata/ruleset/acl_8000", 40) 

for i in range(5):
    resp = ca.query_btree(random.randint(0, 429496729),
            random.randint(0, 429496729),
            random.randint(0, 65535),
            random.randint(0, 65535))

    cnt = 0
    for item in resp:
        s = ""
        if cnt == 0:
            s += "("

        cnt = cnt+1

        if cnt == 8:
            s += str(item)
            s += "); "
            cnt = 0
        else:
            s += str(item)
            s += ", "
        
        print s
