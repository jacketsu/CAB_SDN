import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class SlowPathFloodSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SlowPathFloodSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.t0 = time.time()
        self.byte_cnt = 0
        self.byte_overflow = 0
        self.time_cnt = 0

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        msg = ev.msg
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        print 'OFPSwitchFeatures receive: datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (msg.datapath_id, msg.n_buffers, msg.n_tables,msg.auxiliary_id, msg.capabilities)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, max_len = 46)]
        print "max_len" + str(actions[0].max_len)
        self.add_flow(datapath, 0, match, actions,0)

    def add_flow(self, datapath, priority, match, actions, hard_timeout):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                hard_timeout = hard_timeout,match=match, instructions=inst)

        datapath.send_msg(mod)

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
        self.mac_to_port.setdefault(dpid, {})

        #self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.byte_cnt += msg.msg_len
        out_port = 2 

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        #match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
        #self.add_flow(datapath, 1, match, actions,1)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        self.byte_overflow += len(msg.data)

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.time_cnt += 1
        if self.time_cnt >= 1:
            self.time_cnt = 0
            t1 = time.time()
            if t1 - self.t0 >= 1:
                now = time.time()
                print "%d\t%s\t%s" % (now,self.byte_cnt, self.byte_overflow)
                self.t0 = time.time()
                self.byte_cnt = 0
                self.byte_overflow = 0
