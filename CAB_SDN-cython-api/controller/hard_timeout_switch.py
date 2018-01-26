# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import inet
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
#This switch install flow for different TCP source port and destination port
#and install flow for ARP and ignore other kinds of traffic.
class HardTimeoutSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HardTimeoutSwitch, self).__init__(*args, **kwargs)
        self.hard_timeout = 10
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        self.logger.info('OFPSwitchFeatures datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (msg.datapath_id, msg.n_buffers, msg.n_tables,msg.auxiliary_id, msg.capabilities))
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, hard_timeout_=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, hard_timeout=hard_timeout_, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        if ethertype == ether.ETH_TYPE_ARP: 
            self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)
            
            out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]
            match.set_dl_type(ether.ETH_TYPE_ARP)
            self.add_flow(datapath, 1, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        elif ethertype == ether.ETH_TYPE_IP:
            ip_header = pkt.get_protocol(ipv4.ipv4)
            #handle those not tcp pkt:
            if  ip_header.proto == inet.IPPROTO_TCP:
                #handle tcp pkt
                tcp_header = pkt.get_protocol(tcp.tcp)

                sport = tcp_header.src_port
                dport = tcp_header.dst_port

                out_port = ofproto.OFPP_FLOOD
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch()
                match.set_dl_type(ether.ETH_TYPE_IP)
                match.set_ip_proto(inet.IPPROTO_TCP)
                match.set_tcp_src(sport)
                match.set_tcp_dst(dport)

                match_counter = parser.OFPMatch()
                match_counter.set_dl_type(ether.ETH_TYPE_ARP)
                match_counter.set_ip_proto(inet.IPPROTO_TCP)
                match_counter.set_tcp_src(dport)
                match_counter.set_tcp_dst(sport)

                self.add_flow(datapath, 100, match, actions, self.hard_timeout)
                self.add_flow(datapath, 100, match_counter, actions, self.hard_timeout)
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
