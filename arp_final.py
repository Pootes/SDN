import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, vlan
from ryu.ofproto import ofproto_v1_3
import logging
import logging.handlers


class VLANSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VLANSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.logger.setLevel(logging.INFO)

        # File handler to log events to a file
        file_handler = logging.FileHandler("ryu_events.log")
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

        # Socket handler to send logs to a remote socket
        socket_handler = logging.handlers.SocketHandler('127.0.0.1', 9999)  # Replace with your desired IP/port
        socket_handler.setLevel(logging.INFO)
        socket_handler.setFormatter(formatter)
        self.logger.addHandler(socket_handler)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default table-miss flow entry to send packets to the controller
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        self.logger.info(f"Switch connected: DPID={datapath.id}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)

        datapath.send_msg(mod)
        self.logger.info(f"Flow added: DPID={datapath.id}, Match={match}, Actions={actions}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth:
            self.log_packet_details(pkt, in_port)

        self.handle_packet(datapath, in_port, pkt, msg)

    def handle_packet(self, datapath, in_port, pkt, msg):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
        src = eth.src
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        self.add_flow(datapath, 1, match, actions)

        if msg.buffer_id == 0xffffffff:
            data = pkt.data
        else:
            data = None

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def log_packet_details(self, pkt, in_port):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth_pkt:
            ethertype = eth_pkt.ethertype
            self.logger.info(f"Ethernet Packet: Src={eth_pkt.src}, Dst={eth_pkt.dst}, Ethertype={ethertype}, Port={in_port}")

        if arp_pkt:
            self.logger.info(f"ARP Packet: Opcode={arp_pkt.opcode}, Src_IP={arp_pkt.src_ip}, Dst_IP={arp_pkt.dst_ip}, Src_MAC={arp_pkt.src_mac}, Dst_MAC={arp_pkt.dst_mac}")

    def wireshark_packet_capture(self, pkt, src, dst, in_port, out_port, vlan_id=None):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth_pkt.ethertype

        ether_type_map = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86dd: "IPv6",
            0x8847: "MPLS",
            0x8848: "MPLS",
            0x8100: "VLAN",
        }

        ether_type_str = ether_type_map.get(ethertype, "Unknown")
        self.logger.info(f"Packet captured: Src={src}, Dst={dst}, In_Port={in_port}, Out_Port={out_port}, EtherType={ether_type_str}")
