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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls, HANDSHAKE_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu import utils
import random
from cab_client import *


class CABSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(CABSwitch, self).__init__(*args, **kwargs)
        self.cab = cab_client()
        self.cab.create_connection()
        self.overflow_cnt = 0
        self.is_overflow = False

    def add_flow(self, datapath, table_id, priority,
                 match, inst, buffer_id, hard_timeout=60):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, hard_timeout=hard_timeout,
                                table_id=table_id, priority=priority,
                                match=match, instructions=inst,
                                buffer_id=buffer_id)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # install table-miss flow entry
        self.logger.info('OFPSwitchFeatures datapath_id=0x%016x n_buffers=%d \
                          n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (
                              msg.datapath_id, msg.n_buffers, msg.n_tables,
                              msg.auxiliary_id, msg.capabilities))
        # set table0 default rule: go to controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        self.add_flow(datapath, 0, 0, match, inst, ofproto.OFP_NO_BUFFER, 0)
        # set table1 default : drop
        inst2 = []
        self.add_flow(datapath, 1, 0, match, inst2, ofproto.OFP_NO_BUFFER, 0)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.info('OFPErrorMsg received:\
                         type=0x%02x code=0x%02x message=%s',
                         msg.type, msg.code, utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port = msg.match['in_port']

        # datapath is the object which denotes the link between switch and
        # controller
        datapath = msg.datapath

        # ofproto and parser is version related
        ofproto = datapath.ofproto

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            # data = msg.data
            self.overflow_cnt += 1
            if not self.is_overflow:
                self.is_overflow = True
        else:
            self.is_overflow = False

        # msg.data is raw data.
        pkt = packet.Packet(msg.data)
        # header class:
        # http://ryu.readthedocs.org/en/latest/library_packet_ref.html

        # parse ethernet header
        eth = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth.ethertype

        if ethertype == ether.ETH_TYPE_ARP:
            self.handle_arp(datapath, msg, in_port)
            return

        if ethertype == ether.ETH_TYPE_IP:
            self.handle_ip(datapath, msg, in_port)
            return

    def handle_no_buffer(self, datapath, data, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        req = ofp_parser.OFPPacketOut(
            datapath, ofp.OFP_NO_BUFFER, in_port, actions, data)
        datapath.send_msg(req)

    def send_packet_out(self, datapath, buffer_id, in_port):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
        req = ofp_parser.OFPPacketOut(datapath, buffer_id, in_port, actions)
        datapath.send_msg(req)

    def handle_arp(self, datapath, msg, in_port):
        ofp = datapath.ofproto
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)
        else:
            self.send_packet_out(datapath, msg.buffer_id, in_port)

    def handle_ping(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        match.set_ip_proto(inet.IPPROTO_ICMP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.add_flow(datapath, 0, 200, match, inst, msg.buffer_id, 1)
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)

    def handle_ip(self, datapath, msg, in_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # try to parse ip header
        pkt = packet.Packet(msg.data)
        ip_header = pkt.get_protocol(ipv4.ipv4)
        self.logger.debug('ip src %s dst %s', ip_header.src, ip_header.dst)
        ip_src = ip_header.src
        ip_dst = ip_header.dst

        # try to parse icmp
        if ip_header.proto == inet.IPPROTO_ICMP:
            self.handle_ping(datapath, msg, in_port)
            return
        # try to pars tcp header
        # tcp_header = pkt.get_protocol(tcp.tcp)
        # src_port = tcp_header.src_port
        # dst_port = tcp_header.dst_port
        src_port = 0
        dst_port = 0
        request = pkt_h(ipv4_to_int(ip_src), ipv4_to_int(
            ip_dst), src_port, dst_port)
        rules = self.cab.query(request)

        if rules is None:
            self.logger.error(
                "error\trequest rules for packet failed: %s %s", ip_src, ip_dst)
            return
        # first install rules, rules[0] is bucket
        timeout = random.randint(10, 20)
        for rule in rules[1:]:
            match = parser.OFPMatch()
            match.set_dl_type(ether.ETH_TYPE_IP)
            # match.set_ip_proto(inet.IPPROTO_TCP)
            match.set_ipv4_src_masked(rule.ip_src, rule.ip_src_mask)
            match.set_ipv4_dst_masked(rule.ip_dst, rule.ip_dst_mask)
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            inst = [parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.logger.debug("install flow %s %s %s %s",
                              ipv4_to_str(rule.ip_src),
                              ipv4_to_str(rule.ip_src_mask),
                              ipv4_to_str(rule.ip_dst),
                              ipv4_to_str(rule.ip_dst_mask))
            self.add_flow(datapath, 1, 100 - rules.index(rule) + 1,
                          match, inst, ofproto.OFP_NO_BUFFER, timeout)
        # second, send a barrier to ensure all rules installation are done
        datapath.send_barrier()

        # thrid, install bucket
        bucket = rules[0]
        match = parser.OFPMatch()
        match.set_dl_type(ether.ETH_TYPE_IP)
        # imatch.set_ip_proto(inet.IPPROTO_TCP)
        match.set_ipv4_src_masked(bucket.ip_src, bucket.ip_src_mask)
        match.set_ipv4_dst_masked(bucket.ip_dst, bucket.ip_dst_mask)
        inst = [parser.OFPInstructionGotoTable(1)]
        self.add_flow(datapath, 0, 1, match, inst, msg.buffer_id, timeout)

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            self.handle_no_buffer(datapath, msg.data, in_port)

        self.logger.debug("install bucket %s %s %s %s",
                          ipv4_to_str(bucket.ip_src),
                          ipv4_to_str(bucket.ip_src_mask),
                          ipv4_to_str(bucket.ip_dst),
                          ipv4_to_str(bucket.ip_dst_mask))
