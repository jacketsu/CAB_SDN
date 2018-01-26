import socket
import struct
import sys
import array
import logging
from time import sleep
logger = logging.getLogger("tcp")


class pkt_h:

    def __init__(self, ip_src=0, ip_dst=0, port_src=0, port_dst=0):
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.port_src = port_src
        self.port_dst = port_dst


class bktOrR(object):
    def __init__(self, ip_src=0, ip_src_mask=0, ip_dst=0, ip_dst_mask=0, port_src=0,
                 port_src_mask=0, port_dst=0, port_dst_mask=0, priority=0):
        self.ip_src = ip_src
        self.ip_src_mask = ip_src_mask
        self.ip_dst = ip_dst
        self.ip_dst_mask = ip_dst_mask
        self.port_src = port_src
        self.port_src_mask = port_src_mask
        self.port_dst = port_dst
        self.port_dst_mask = port_dst_mask
        self.priority = priority

    def __str__(self):
        return "%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t" \
            % (self.ip_src, self.ip_src_mask,
               self.ip_dst, self.ip_dst_mask,
               self.port_src, self.port_src_mask,
               self.port_dst, self.port_dst_mask, self.priority)


def ipv4_to_str(integer):
    ip_list = [str((integer >> (24 - (n * 8)) & 255)) for n in range(4)]
    return '.'.join(ip_list)


# TODO: verify this function
def ipv4_port_to_ipv6(ipv4, ipv4_mask, port, port_mask):
    # process ip
    ip_list = [hex(ipv4 >> (48 - (n * 16)) & 65535) for n in range(4)]
    port_list = [hex(port >> (48 - (n * 16)) & 65535) for n in range(4)]
    ipv6 = ':'.join(port_list + ip_list)

    # process tcp port
    ip_mask_list = [hex(ipv4_mask >> (48 - (n * 16)) & 65535) for n in range(4)]
    port_mask_list = [hex(port_mask >> (48 - (n * 16)) & 65535) for n in range(4)]
    ipv6_mask = ':'.join(port_mask_list + ip_mask_list)

    return (ipv6, ipv6_mask)

def ipv4_to_int(string):
    ip = string.split('.')
    assert len(ip) == 4
    i = 0
    for b in ip:
        b = int(b)
        i = (i << 8) | b
    return i




def eth_to_str(integer):
    eth_list = [hex(integer >> (44 - (n * 8)) & 15)[2:] +
                hex(integer >> (40 - (n * 8)) & 15)[2:] for n in range(6)]
    return ':'.join(eth_list)


def eth_mask_to_str(integer):
    eth_list = [hex(integer >> (44 - (n * 8)) & 15)[2:] +
                hex(integer >> (40 - (n * 8)) & 15)[2:] for n in range(6)]
    mask_temp = ':'.join(eth_list)
    return 'ff:ff:' + mask_temp[6:]


def eth_to_int(string):
    eth = string.split(':')
    assert len(eth) == 6
    i = 0
    for b in eth:
        b = int(b, 16)
        i = (i << 8) | b
    return i
##########################################################################


class cab_client:

    def __init__(self):
        self.server_ip = '127.0.0.1'
        self.server_port = 9000
        self.header_size = 4
        self.skt = None

    def create_connection(self):
        if self.skt == None:
            try:
                self.skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.skt.connect((self.server_ip, self.server_port))
                logger.info("server connected : %s %s",
                            self.server_ip, self.server_port)
            except socket.error as e:
                logger.debug("error connected %s,%s", e.errno, e.message)
                self.handle_error()

    def handle_error(self):
        if self.skt != None:
            try:
                self.skt.close()
            finally:
                self.skt = None

    def query(self, request):
        if not isinstance(request, pkt_h):
            return None
        if self.skt == None:
            self.create_connection()
        if self.skt == None:
            return None
        # construct request
        request_len = 16
        message = struct.pack('!IIIII', request_len, request.ip_src,
                              request.ip_dst, request.port_src, request.port_dst)
        try:
            # send request
            self.skt.send(message)

            # recv header
            body_len_raw = self.skt.recv(self.header_size)
            # parse header to get body length
            (body_len,) = struct.unpack('!I', body_len_raw)
            # recv body
            body_raw = self.skt.recv(body_len)
        except socket.error, (value, message):
            logger.error("TCP ERROR:\t%s %s", value, message)
            logger.info("TCP INFO:\ttry to re-connect " +
                        self.server_ip + " : " + str(self.server_port))
            self.handle_error()
            return None
        except struct.error:
            self.handle_error()
            return None

        rules_num = body_len / 36
        rules = []
        for i in range(rules_num):
            rules.append(bktOrR())
            # include port
            (rules[i].ip_src, rules[i].ip_src_mask,
             rules[i].ip_dst, rules[i].ip_dst_mask,
             rules[i].port_src, rules[i].port_src_mask,
             rules[i].port_dst, rules[i].port_dst_mask,
             rules[i].priority) = struct.unpack('!IIIIIIIII',
                                                 body_raw[i * 36: i * 36 + 36])
        return rules

# for test
if __name__ == "__main__":
    src = ipv4_to_int('10.0.0.1')
    dst = ipv4_to_int('10.0.0.2')
    src_str = ipv4_to_str(src)
    dst_str = ipv4_to_str(dst)
    print "int : %s %s" % (src, dst)
    print "str : %s %s" % (src_str, dst_str)
    request = pkt_h(src, dst, 4000, 8000)
    cab = cab_client()
    cab.create_connection()
    rules = cab.query(request)
    for i in rules:
        print i
