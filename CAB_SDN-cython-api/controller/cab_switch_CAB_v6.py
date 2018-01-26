# Copyright (C) 2014 High Speed Network Labtory, Polytechnic School of Engineering, NYU
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import threading
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import HANDSHAKE_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import mac
from ryu.lib.packet import ipv6
from ryu import utils
import random
from cab_client import *

# from ryu.lib import ip
# from ryu.lib.packet import tcp
# import struct


class CABSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CABSwitch, self).__init__(*args, **kwargs)
        self.cab = cab_client()
        self.cab.create_connection()
        self.overflow_cnt = 0
        self.is_overflow = False
        self.queries = 0
        self.packetin = 0
        self.packetout = 0
        self.flowmod = 0
        self.tracefile = raw_input('Enter Tracename: ')
        self.buckets = {}
        self.query_map = {}
        # open('buckets', 'w').close()
        # open('queries', 'w').close()

    def add_flow(self, datapath, table_id, priority,
                 match, inst, buffer_id, hard_timeout=60):

        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,
                                hard_timeout=hard_timeout,
                                table_id=table_id,
                                priority=priority,
                                match=match,
                                instructions=inst,
                                buffer_id=buffer_id)
        datapath.send_msg(mod)
        self.flowmod += 1

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        self.logger.info('OFPSwitchFeatures datapath_id=0x%016x \
                         n_buffers=%d n_tables=%d auxiliary_id=%d \
                         capabilities=0x%08x'
                         % (msg.datapath_id,
                            msg.n_buffers,
                            msg.n_tables,
                            msg.auxiliary_id,
                            msg.capabilities))

        # First, clear table entries
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)

        # set table0 default rule:
        # port1->port2: go to controller
        match = parser.OFPMatch(in_port=1)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath, 0, 0, match, inst, ofproto.OFP_NO_BUFFER, 0)

        # port2: go to port 1
        match = parser.OFPMatch(in_port=2)
        actions = [parser.OFPActionOutput(1, 0)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath, 0, 0, match, inst, ofproto.OFP_NO_BUFFER, 0)

        # set table1 default : drop
        match = parser.OFPMatch()
        inst2 = []
        self.add_flow(datapath, 1, 0, match, inst2, ofproto.OFP_NO_BUFFER, 0)

        m = threading.Thread(target=self.monitor)
        m.start()
        c = threading.Thread(target=self.clean_query_map)
        c.start()

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPErrorMsg received: type=0x%02x \
                         code=0x%02x message=%s',
                         msg.type, msg.code, utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        self.packetin += 1
        msg = ev.msg
        in_port = msg.match['in_port']

        # datapath is the object
        # which denotes the link between switch and controller
        datapath = msg.datapath
        # dpid = datapath.id

        # ofproto and parser is version related
        ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            # data = msg.data
            self.overflow_cnt += 1
            if not self.is_overflow:
                # logger.warning('warning\tswitch packet-in overflow %d',
                # self.overflow_cnt)
                self.is_overflow = True
        else:
            self.is_overflow = False

        # msg.data is raw data.
        # pkt = packet.Packet(msg.data)
        # header class:
        # http://ryu.readthedocs.org/en/latest/library_packet_ref.html

        # parse ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)
        # eth_dst = eth.dst
        # eth_src = eth.src
        ethertype = eth.ethertype

        if ethertype == ether.ETH_TYPE_ARP:
            self.send_packet_out(datapath, msg, in_port)
            return

        if ethertype == ether.ETH_TYPE_IPV6:
            self.handle_ipv6(datapath, msg, in_port)
            return

    def handle_no_buffer(self, datapath, data, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(3)]
        req = ofp_parser.OFPPacketOut(datapath,
                                      ofp.OFP_NO_BUFFER,
                                      in_port, actions, data)
        datapath.send_msg(req)
        self.packetout += 1

    def send_packet_out(self, datapath, msg, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)
        else:
            actions = [ofp_parser.OFPActionOutput(3)]
            req = ofp_parser.OFPPacketOut(datapath, msg.buffer_id,
                                          in_port, actions)
            datapath.send_msg(req)

    def handle_ping(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_ICMP)
        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath, 0, 200, match, inst, msg.buffer_id, 1)

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)

    def handle_ipv6(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # try to parse ip header
        pkt = packet.Packet(msg.data)
        ip_header = pkt.get_protocol(ipv6.ipv6)
        self.logger.debug('ip src %s dst %s', ip_header.src, ip_header.dst)
        ip_src = ip_header.src
        ip_dst = ip_header.dst

        # try to parse icmp
        if ip_header.nxt == inet.IPPROTO_ICMP:
            self.handle_ping(datapath, msg, in_port)
            return

        if ip_header.nxt != inet.IPPROTO_TCP:
            self.send_packet_out(datapath, msg, in_port)
            return

        # try to parse tcp ports converted from higher bits of ipv6
        # TODO confirm the LSB/MSB of port and ip
        ip_src = ip_src & 0x0000000000000000ffffffffffffffff
        ip_dst = ip_dst & 0x0000000000000000ffffffffffffffff
        src_port = ip_src >> 64
        dst_port = ip_dst >> 64

        key = ip_src + ip_dst + str(src_port) + str(dst_port)

        # Each flow sends only the first packet
        if key in self.query_map:
            self.send_packet_out(datapath, msg, in_port)
            return
        self.query_map[key] = time.time()

        # debug:check the ipv4 and port from switch to controller through OpenFLow
        print(ip_src, ip_ds, src_port, dst_port)
        request = pkt_h(ip_src, ip_dst,
                        src_port, dst_port)

        # request_str = str(ip_src)+'\t'+str(ip_dst)+ \
        # '\t'+str(eth.src)+'\t'+str(eth.dst)+'\n'
        # with open('queries', 'a') as q:
        #         string = str(time.time()) + '\t' + request_str + '\n'
        #         q.write(string)
        # print string

        self.queries += 1
        rules = self.cab.query(request)

        if rules is None:
            self.logger.error("error\trequest rules for packet failed: \
                              %s %s", ip_src, ip_dst)
            return

        timeout = random.randint(20, 30)  # randomize the timeout

        # If there is more than one query hit the
        # same bucket before the bucket been installed,
        # only need to flowmod the bucket once.

        bucket = rules[0]

        bucket_str = ipv4_to_str(bucket.ip_src) + '/' \
            + ipv4_to_str(bucket.ip_src_mask) + '\t' \
            + ipv4_to_str(bucket.ip_dst) + '/' \
            + ipv4_to_str(bucket.ip_dst_mask) + '\t' \
            + str(bucket.port_src) + '/' \
            + str(bucket.port_src_mask) + '\t' \
            + str(bucket.port_dst) + '/'\
            + str(bucket.port_dst_mask)

        if bucket_str not in self.buckets:
            self.buckets[bucket_str] = time.time() + timeout
            # with open('buckets', 'a') as f:
            #     string = str(time.time()) + '\t' + bucket_str + '\n'
            #     f.write(string)
        elif self.buckets[bucket_str] < time.time():
            self.buckets[bucket_str] = time.time() + timeout
        else:
            self.send_packet_out(datapath, msg, in_port)
            return

        # first install rules, rules[0] is bucket
        # TODO: ryu translate ipv4/port&mask to ipv6&bitmask
        for rule in rules[1:]:
            match = parser.OFPMatch(in_port=1, eth_type=ether.ETH_TYPE_IPV6,
                                    ipv6_src=ipv4_port_to_ipv6(rule.ip_src,
                                                               rule.ip_src_mask,
                                                               rule.port_src,
                                                               rule.port_src_mask),
                                    ipv6_dst=ipv4_port_to_ipv6(rule.ip_dst,
                                                               rule.ip_dst_mask,
                                                               rule.port_dst,
                                                               rule.port_dst_mask))
            actions = [parser.OFPActionOutput(2)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            self.add_flow(datapath, 1, rule.priority,
                          match, inst, ofproto.OFP_NO_BUFFER, timeout)

            self.logger.debug("install flow %s, %s",
                              str(ipv4_port_to_ipv6(rule.ip_src,
                                                    rule.ip_src_mask,
                                                    rule.port_src,
                                                    rule.port_src_mask)),
                              str(ipv4_port_to_ipv6(rule.ip_dst,
                                                    rule.ip_dst_mask,
                                                    rule.port_dst,
                                                    rule.port_dst_mask)))


        # second, send a barrier to ensure all rules installation are done
        datapath.send_barrier()

        # third, install bucket
        bucket = rules[0]
        match = parser.OFPMatch(in_port=1, eth_type=ether.ETH_TYPE_IPV6,
                                ipv6_src=ipv4_port_to_ipv6(bucket.ip_src,
                                                           bucket.ip_src_mask,
                                                           bucket.port_src,
                                                           bucket.port_src_mask),
                                ipv6_dst=ipv4_port_to_ipv6(bucket.ip_dst,
                                                           bucket.ip_dst_mask,
                                                           bucket.port_dst,
                                                           bucket.port_dst_mask))

        inst = [parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath, 0, 100, match, inst, msg.buffer_id, timeout)

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)

        self.logger.debug("install bucket %s %s",
                          str(ipv4_port_to_ipv6(bucket.ip_src,
                                                bucket.ip_src_mask,
                                                bucket.port_src,
                                                bucket.port_src_mask)),
                          str(ipv4_port_to_ipv6(bucket.ip_dst,
                                                bucket.ip_dst_mask,
                                                bucket.port_dst,
                                                bucket.port_dst_mask)))

    def monitor(self):
        with open('./results_cab_'+self.tracefile, 'w') as f:
            f.write('time\tqueries\tPacketIn\tFlowMod\n')
            while True:
                string = str(time.time()) + '\t' \
                    + str(self.queries) + '\t'\
                    + str(self.packetin) + '\t'\
                    + str(self.flowmod)+'\n'
                f.write(string)

                time.sleep(1)

    def clean_query_map(self):
        while True:
            time.sleep(10)
            for i in self.query_map.keys():
                if (time.time() - self.query_map[i]) > 8:
                    del self.query_map[i]
