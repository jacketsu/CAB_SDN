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
from ryu.controller.handler import HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ofproto_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import mac
from ryu import utils
import time

class record:
    def __init__(self, cookie, timestamp):
        self.cookie=cookie
        self.timestamp=timestamp
#This switch will install two direction flows in switch with two seconds hard timeout
#for each comming new flows.
#It will randomly remove one flows in switch once it recieves table full error message
#from switch.
class TableOverFlowSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TableOverFlowSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.entries_list = []
        self.cookie = 0
        self.timeout = 5

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        msg = ev.msg
        print 'OFPSwitchFeatures receive: datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (msg.datapath_id, msg.n_buffers, msg.n_tables,msg.auxiliary_id, msg.capabilities)
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,max_len=40)]
        self.add_flow(datapath, 0, match, actions,0)
        
        match1 = parser.OFPMatch()
        mac_src1 = mac.haddr_to_bin('00:00:00:00:00:00')
        mac_dst1 = mac.haddr_to_bin('00:00:00:00:00:01')
        mac_mask = mac.haddr_to_bin('ff:ff:ff:ff:ff:ff')
        match1.set_dl_src_masked(mac_src1,mac_mask)
        match1.set_dl_dst_masked(mac_dst1,mac_mask)
        actions1 = [parser.OFPActionOutput(port=2)]
        self.add_flow(datapath,0,match1,actions1,0) 
        
        match2 = parser.OFPMatch()
        mac_src2 = mac.haddr_to_bin('00:00:00:00:00:01')
        mac_dst2 = mac.haddr_to_bin('00:00:00:00:00:00')
        match2.set_dl_src_masked(mac_src2,mac_mask)
        match2.set_dl_dst_masked(mac_dst2,mac_mask)

        actions2 = [parser.OFPActionOutput(port=1)]
        self.add_flow(datapath,1,match2,actions2,0) 


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        
        #install rule
        out_port = 2
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        self.add_flow(datapath, 1, match, actions,hard_timeout=2)

        #packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPErrorMsg,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        err_msg = ev.msg
        #self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x message=%s', msg.type, msg.code, utils.hex_array(msg.data))
        if err_msg.type == ofproto_v1_3.OFPET_FLOW_MOD_FAILED and err_msg.code == ofproto_v1_3.OFPFMFC_TABLE_FULL:
            print 'caputred full table error message'
            self.rand_remove(err_msg.datapath)
            #parser = err_msg.datapath.ofproto_parser
            (version,msg_type,msg_len,xid)= ofproto_parser.header(err_msg.data)
            print 'version %s, msg_type %s, msg_len %s, xid %s, len %s' % (version, msg_type, msg_len, xid, len(err_msg.data))
            msg = ofproto_parser.msg(err_msg.datapath, version,msg_type,msg_len,xid,err_msg.data)
            #controller will assign a new xid
            msg.xid=None
            error_msg.datapath.send_msg(msg)

    def add_flow(self, datapath, priority, match, actions, hard_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        cookie_mask=0xfffffffffffffff
        mod = parser.OFPFlowMod(datapath=datapath,
                                cookie=self.cookie,
                                cookie_mask=cookie_mask,
                                priority=priority,
                                match=match, 
                                instructions=inst, 
                                hard_timeout=hard_timeout)
        datapath.send_msg(mod)
        self.entries_list.append(record(self.cookie,time.time()))
        self.cookie += 1
    def remove_flow(self,datapath,cookie,match):
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,command=ofproto_v1_3.OFPFC_DELETE,match=match)
    def rand_remove(self,datapath):
            now = time.time()
            out = []
            find = None 
            for i in self.entries_list:
                if now - i.timestamp <= self.timeout:
                    if find != None:
                        out.append(i)
                    else:
                        find = i
            self.entries_list = out
            match = datapath.ofproto_parser.OFPMatch()
            self.remove_flow(datapath, find.cookie, match)
