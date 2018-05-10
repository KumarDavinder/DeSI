from ryu.base import app_manager
from ryu.controller.handler import set_ev_cls
from ryu.services.protocols.bgp import application as bgp_application
from ryu.services.protocols.bgp.base import BGPSException
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
from ryu.topology import event
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER
from ryu.ofproto import ofproto_v1_3, ether
from ryu.ofproto.ofproto_v1_3 import OFP_NO_BUFFER
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, arp,icmp, tcp
import os
from ryu import cfg
from ryu.utils import load_source
from ryu.services.protocols.bgp.rtconf.common import ROUTER_ID
from ryu.services.protocols.bgp.rtconf.common import LOCAL_AS
from policy_container import *
from pprint import pprint
import socket
import struct
from collections import OrderedDict
import json


CONF = cfg.CONF['bgp-app']
class ApplicationException(BGPSException):
    """
    Specific Base exception related to `BSPSpeaker`.
    """
    pass

def load_config(config_file):
    """
    Validates the given file for use as the settings file for BGPSpeaker
    and loads the configuration from the given file as a module instance.
    """
    if not config_file or not os.path.isfile(config_file):
        raise ApplicationException(
            desc='Invalid configuration file: %s' % config_file)
    # Loads the configuration from the given file, if available.
    try:
        return load_source('bgpspeaker.application.settings', config_file)
    except Exception as e:
        raise ApplicationException(desc=str(e))

class Policy_Selector(app_manager.RyuApp):
    _CONTEXTS = {
        'ryubgpspeaker': bgp_application.RyuBGPSpeaker
    }

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # To observe network's events
    app_manager.require_app('ryu.topology.switches')

    def __init__(self, *args, **kwargs):
        super(Policy_Selector, self).__init__(self, *args, **kwargs)
        self.RyuBGPSpeaker = kwargs['ryubgpspeaker']
        self.kwargs = kwargs
        self.config_file = CONF.config_file
        self._settings = None
        self.controller_ip = None
        self.controller_mac = None
        self.router_ip1 = None
        self.router_mac1 = None
        self.router_ip2 = None
        self.router_mac2 = None
        self.INFO_OTHER_AS = None
        self.subnet = None
        self.packet = None
        self.network = None
        if self.config_file:
            self._settings = load_config(self.config_file)
            self.controller_ip = self._settings.SWITCH_CONTROLLER_INFO.get('controller_ip')
            self.controller_mac = self._settings.SWITCH_CONTROLLER_INFO.get('controller_mac')
            self.router_ip1 = self._settings.SWITCH_CONTROLLER_INFO.get('router_ip1')
            self.router_mac1 = self._settings.SWITCH_CONTROLLER_INFO.get('router_mac1')
            self.router_ip2 = self._settings.SWITCH_CONTROLLER_INFO.get('router_ip2')
            self.router_mac2 = self._settings.SWITCH_CONTROLLER_INFO.get('router_mac2')
            self.subnet = self._settings.SWITCH_CONTROLLER_INFO.get('subnet')
            self.INFO_OTHER_AS = self._settings.INFO_ON_OTHER_AS
        #this is policy_selector.py
        self.list_rule_action = get_list_rule_action('hosthome/Desktop/DeSI/politiche_in_input.json')
        #self.list_rule_action = get_list_rule_action('hosthome/Desktop/DeSI/varioPolitiche.json')

        self.dictionary_graph_dependence = get_dict_graph_dependence(self.list_rule_action)
        self.dictionary_cover_set = get_dict_covers(self.list_rule_action)
        #print "graph dependence map: "+str(self.dictionary_graph_dependence)
        #print "cover map: "+str(self.dictionary_cover_set)
        #print
        #for index in range(0, self.list_rule_action.__len__()):
        #    print str(index)+") "+str(self.list_rule_action[index][0]) + " --> " + str(self.list_rule_action[index][1])
        #print "*************************************************************************************"

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        #print "ciao"
        datapath = ev.switch.dp
        parser=datapath.ofproto_parser
        ofproto=datapath.ofproto
        #print 'Switch %s joint!' % hex(datapath.id)
        #print 'Switch information:', datapath.ports
        #per la deflection
        self.network = datapath

        #le seguenti due regole sono per gestire il peering tra controller
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_dst = (str(self.controller_ip)))
        actions = [parser.OFPActionSetField(eth_dst=self.controller_mac), parser.OFPActionOutput(port = 2)]
        self.add_flow(datapath, 10 , match, actions, 0)

        """match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_src = '50.0.0.3', ipv4_dst = '5.0.0.1')
        actions = [parser.OFPActionOutput(port = 5)]
        self.add_flow(datapath, 10 , match, actions)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_src = '5.0.0.1', ipv4_dst = '50.0.0.3')
        actions = [parser.OFPActionOutput(port = 4)]
        self.add_flow(datapath, 10 , match, actions)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_src = '50.0.0.2', ipv4_dst = '5.0.0.2')
        actions = [parser.OFPActionOutput(port = 4)]
        self.add_flow(datapath, 10 , match, actions)

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_src = '5.0.0.2', ipv4_dst = '50.0.0.2')
        actions = [parser.OFPActionOutput(port = 4)]
        self.add_flow(datapath, 10 , match, actions)"""

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, in_port = 2)
        actions = [parser.OFPActionOutput(port = 1)]
        self.add_flow(datapath, 4, match, actions, 0)

        """un pacchetto puo' arrivare a me controler solo se eth_dst e' quello del mio switch"""
        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, eth_dst = self.INFO_OTHER_AS.get(self.controller_ip))
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 4, match, actions, 0)
        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, in_port = 1)
        self.add_flow(datapath,3, match, [], 0)

        """a me controller 3 mi arrivano pacchetti che si mandano 1-2 perche' non matchando nessuna regola 
        allora vengono mandati a me"""
        """match= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_src = ('5.0.0.0','255.255.255.0'), ipv4_dst= ('5.0.0.0','255.255.255.0'))
        self.add_flow(datapath,2, match, [])"""
        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_src = ('50.0.0.0','255.255.255.0'), ipv4_dst= ('50.0.0.0','255.255.255.0'))
        self.add_flow(datapath,2, match, [], 0)

        #le seguenti due regole servono invece per evitare di mandare i pacchetti di peering al
        #controller (pacchetti che non sono diretti a controller)
        #questo serve ma lo uso all'ultimo perche adesso voglio vedere la tabella bgp
        """match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, tcp_src = 179)
        self.add_flow(datapath, 155 , match, [])

        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, tcp_dst = 179)
        self.add_flow(datapath, 155 , match, [])"""
        

        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, arp_tpa = self.controller_ip)
        actions=[parser.OFPActionOutput(port=2)]
        self.add_flow(datapath,10, match, actions, 0)

        """match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=2, arp_spa = '50.0.0.3', arp_tpa = '5.0.0.1')
        actions=[parser.OFPActionOutput(port=5)]
        self.add_flow(datapath,10, match, actions)

        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=2, arp_spa = '5.0.0.1', arp_tpa = '50.0.0.3')
        actions=[parser.OFPActionOutput(port=4)]
        self.add_flow(datapath,10, match, actions)

        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=2, arp_spa = '50.0.0.2', arp_tpa = '5.0.0.2')
        actions=[parser.OFPActionOutput(port=4)]
        self.add_flow(datapath,10, match, actions)

        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=2, arp_spa = '5.0.0.2', arp_tpa = '50.0.0.2')
        actions=[parser.OFPActionOutput(port=4)]
        self.add_flow(datapath,10, match, actions)

        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=2, arp_tpa = ('5.0.0.0','255.255.255.0'))
        actions=[parser.OFPActionOutput(port=1)]
        self.add_flow(datapath,5, match, actions)"""

        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, in_port=2, arp_tpa = ('50.0.0.0','255.255.255.0'))
        actions=[parser.OFPActionOutput(port=1)]
        self.add_flow(datapath,5, match, actions, 0)
        
        """tolgo anche i arp non diretti a me...se metti /16 si perde il peering 3-5...5.0.1.5...50.0.1.5 sono of5 e of3"""
        """match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, arp_tpa = ('5.0.0.0','255.255.255.0'), arp_spa = ('5.0.0.0','255.255.255.0'))
        self.add_flow(datapath,3, match, [])"""
        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_ARP, arp_tpa = ('50.0.0.0','255.255.255.0'), arp_spa = ('50.0.0.0','255.255.255.0'))
        self.add_flow(datapath,3, match, [], 0)

        #match = parser.OFPMatch()
        #actions = [parser.OFPInstructionGotoTable(1)]
        #self.add_flow_for_goto(datapath, 0, match, actions, 0)
        #self.create_second_table(datapath, parser)
        #self.create_third_table(datapath, parser)

    def create_second_table(self, datapath, parser):
        #take the full bgp table from the file not the bgp table after peering
        with open('hosthome/Desktop/DeSI/BGP_table.json') as input_bgp_table_json:
            bgpTablejson = json.load(input_bgp_table_json)
        #bgpTablejson = []
        for paths_prefix in bgpTablejson:
            list_aspath = []
            prefix = paths_prefix["prefix"]
            #print "\n"
            #print prefix
            paths = paths_prefix["paths"]
            for path in paths:
                aspath = path["aspath"]
                if aspath.__len__() == 0:
                    list_aspath.append(self._settings.BGP.get('local_as'))
                else:
                    list_aspath.append(aspath[0])
            metadata = int(self.create_metadata_for_second_table(list_aspath), 2)
            net = ipaddr.IPNetwork(prefix)
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6, ipv4_dst=(net.ip, net.netmask))
            actions = [parser.OFPInstructionGotoTable(2), parser.OFPInstructionWriteMetadata(metadata=metadata, metadata_mask=parser.UINT64_MAX)]
            self.add_flow_for_goto(datapath, 100, match, actions, 1)

    def create_third_table(self, datapath, parser):
        key = 0
        for rule_action in self.list_rule_action:
            rule = rule_action[0]
            list_sub_policy = rule.split(" ")
            list_dictionary = []
            for sub_policy in list_sub_policy:
                match_fields = sub_policy.split("_and_")
                dictionary = {}
                for field in match_fields:
                    f = field.split("=")
                    if field.__contains__("tcp"):
                        dictionary.update({str(f[0]):int(f[1])})
                    elif field.__contains__("ipv4"):
                        net = ipaddr.IPNetwork(f[1])
                        if f[1].split("/").__len__() == 2:
                            dictionary.update({str(f[0]):(net.ip, net.netmask)})
                        else:
                            dictionary.update({f[0]:net.ip})
                list_dictionary.append(dictionary)
            parser = datapath.ofproto_parser
            #print "##############################################################"
            #print key
            list_action = rule_action[1]
            positionInsidePolicy = 0
            key = key + 1
            for action in list_action:
                positionInsidePolicy = positionInsidePolicy + 1
                wildcard = self.create_metadata_for_third_table(action)
                mask = int(self.create_mask(wildcard), 2)
                value = int(self.create_value(wildcard), 2)
                #print mask
                #print value
                priority = self.getPriority(key, positionInsidePolicy)
                #print "priority="+str(priority)
                nexthop_mac = self.INFO_OTHER_AS.get(str(action))
                #print str(action)+" "+str(nexthop_mac)
                #print list_dictionary
                for dictionary in list_dictionary:
                    #print dictionary
                    match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, metadata=(value, mask), **dictionary) 
                    actions = [parser.OFPActionSetField(eth_dst=nexthop_mac), parser.OFPActionOutput(port = 1)]
                    self.add_flow(datapath, priority, match, actions, 2)
        """immagino che nel modo proactive tutto sta nelle tabelle dello switch...se arrivo alla terza regola e non
            matcho nessuna regola allora devo applicare la best...e quindi mando il paccheto al controller...nella
            seconda tabella servirebbe installare una regola che manda i pacchetti al controller? si perche' se stai 
            in ambiente dinamico allora ci puo' essere un add di un prefisso (ma noi siamo in ambiente statico e quindi
            la _switch_features_handler forse non va bene per la tabella 2...ma puo' tornare utile perche' se io invio un
            pacchetto a 9.9.9.9 e questo prefisso non e' presente nella prima tabella allora devo forse scartare il pacchetto
            ma forse nemmeno questa situazione puo' verificarsi).
        """
        match= parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto = 6)
        actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_CONTROLLER, datapath.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 4, match, actions, 2)

    def create_mask(self, wildcard):
        mask = ""
        for elem in wildcard:
            if elem.__eq__("*"):
                mask=mask+"0"
            else:
                mask=mask+"1"
        return mask

    def create_value(self, wildcard):
        value = ""
        for elem in wildcard:
            if elem.__eq__("1"):
                value=value+"1"
            else:
                value=value+"0"
        return value

    def create_metadata_for_third_table(self, action):
        #AS20 prendo 2
        #print action
        as_number = int(str(action)[2])
        code_list = ["*","*","*","*"]
        code_list[as_number-1] = 1
        string_metadata = ""
        for elem in code_list:
            string_metadata = string_metadata+str(elem)
        return string_metadata

    def create_metadata_for_second_table(self, list_aspath):
        code_list = [0,0,0,0]
        for elem in list_aspath:
            number = int(str(elem)[0])
            code_list[number-1] = 1
        string_metadata = ""
        for elem in code_list:
            string_metadata = string_metadata+str(elem)
        return string_metadata

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_CONTROLLER,
                                          max_len=ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(type_=ofproto.OFPIT_APPLY_ACTIONS,
                                             actions=actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=0,
                                table_id=0,
                                match=parser.OFPMatch(),
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        #print('**** I`ve received a packet-in *****')
        """Spiegazione delle tre righe sotto commentate
        per ottenere la tabella BGP (necessaria per riempire la seconda tabella - prefix, metadata), una volta che 
        il peering e' stabilito invio il pacchetto a un controller e mi stampo la sua tabella BGP (questo perche' il 
        sistema e' statico e non si e' fatta un implementazione dinamica per aggiornare la seconda tabella)"""
        #print self.RyuBGPSpeaker.speaker.rib_get('ipv4','json')
        #with open('hosthome/Desktop/DeSI/tabellaBGP.txt', 'w') as outfile:
        #    json.dump(json.loads(self.RyuBGPSpeaker.speaker.rib_get('ipv4','json')), outfile)
        msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        #Per gestire la deflection mi serve il pacchetto
        self.set_packet(pkt)
        #print pkt
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if not pkt_ethernet:
            return
        elif pkt_arp:
            self._handle_arp(datapath, port, pkt_ethernet, pkt_arp)
            return
        elif pkt_ipv4:
            pkt_icmp = pkt.get_protocol(icmp.icmp)
            pkt_tcp = pkt.get_protocol(tcp.tcp)
            #per gestire pacchetti peering sono state installate regole nello switch
            if pkt_icmp:
                #per fare ping Echo-Req e Echo-Reply
                if str(pkt_ipv4.dst).__eq__(str(self.controller_ip)):
                    #print "e' per me controller icmp"
                    self._handle_icmp(datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp)
                elif str(pkt_ipv4.dst).__eq__(str(self.router_ip1)):
                    #print "e' per il primo router icmp"
                    pkt.get_protocol(ethernet.ethernet).dst = self.router_mac1
                    self._send_packet(datapath, 3, pkt)
                elif str(pkt_ipv4.dst).__eq__(str(self.router_ip2)):
                    #print "e' per il secondo router icmp"
                    #print pkt
                    pkt.get_protocol(ethernet.ethernet).dst = self.router_mac2
                    self._send_packet(datapath, 4, pkt) 
                elif port == 3:
                    if str(pkt_ipv4.dst).__eq__(str(self.router_ip2)):
                        self._send_packet(datapath, 4, pkt)
                    self._send_packet(datapath, 1, pkt)
                elif port == 4:
                    if str(pkt_ipv4.dst).__eq__(str(self.router_ip1)):
                        self._send_packet(datapath, 3, pkt)
                    self._send_packet(datapath, 1, pkt)
                elif ((self.subnet is not None) and is_ip1_subnet_of_ip2(str(pkt_ipv4.dst), str(self.subnet))):
                    #se non faccio questo succede che mando un pacchetto icmp echo da 11.0.0.2 a 33.0.0.2
                    #questo pacchetto viene ricevuto da tutti i controller e il controller C2 quello che fa e' di mandare
                    #il pkt al suo router 1 e questo router poiche non sa cosa fare e come default manda il pacchetto allo switch
                    #print "posso scegliere a quale router mandare...mando al primo, icmp"
                    #print pkt
                    pkt.get_protocol(ethernet.ethernet).dst = self.router_mac1
                    self._send_packet(datapath, 3, pkt)
            elif pkt_tcp and (not(int(pkt_tcp.src_port) == 179) and not(int(pkt_tcp.dst_port) == 179)):
                if port == 1 or port == 3 or port == 4 or port == 5:
                    bgpTablejson = self.get_BGP_table()
                    src_port = int(pkt_tcp.src_port)
                    dst_port = int(pkt_tcp.dst_port)
                    src_ipv4 = str(pkt_ipv4.src)
                    dst_ipv4 = str(pkt_ipv4.dst)
                    #print src_ipv4
                    #print dst_ipv4
                    #print src_port
                    #print dst_port
                    """for index in range(0, self.list_rule_action.__len__()):
                        print str(index) + ") " + str(self.list_rule_action[index][0]) + " --> " + str(self.list_rule_action[index][1])
                    #print "\n"
                    #print "cover"
                    #print self.dictionary_cover_set"""
                    list_paths_prefix = self.get_list_paths_prefix(bgpTablejson, dst_ipv4)
                    #print self.RyuBGPSpeaker.speaker.rib_get('ipv4','json')
                    stop = False
                    policies_to_load = None
                    if list_paths_prefix.__len__() is not 0:
                        if port is not 1:
                            for index in range(0, self.list_rule_action.__len__()):
                                policy = str(self.list_rule_action[index][0])
                                action = self.list_rule_action[index][1]
                                subPolicies = policy.split(" ")
                                for subPolicy in subPolicies:
                                    boolean = self.is_this_policy_matching_with_the_packet(subPolicy, src_port, dst_port, src_ipv4, dst_ipv4)
                                    if boolean:
                                        dict_paths = self.get_paths(action, list_paths_prefix)
                                        if dict_paths.__len__() is not 0:
                                            stop = True
                                            policies_to_load = OrderedDict()
                                            policies_to_load = self.add_policy_to_load_on_switch(dict_paths, index, policies_to_load)
                                            for policyNumber in self.dictionary_graph_dependence[index]:
                                                dict_paths = self.get_paths(self.list_rule_action[policyNumber][1], list_paths_prefix)
                                                if dict_paths.__len__() is not 0:
                                                    policies_to_load = self.add_policy_to_load_on_switch(dict_paths, policyNumber, policies_to_load)
                                            self.load_rule_on_switch(datapath, policies_to_load) 
                                            #print "\nIl controller invia il pacchetto sulla porta OFPP_TABLE"
                                            #forse non e' necessario pkt_ethernet.src = self.INFO_OTHER_AS.get(self.controller_ip)
                                            self._send_packet(datapath, datapath.ofproto.OFPP_TABLE, pkt)
                                    if stop:
                                        break
                                if stop:
                                    break
                        if not stop:
                            path = self.get_best(list_paths_prefix)
                            if path: #forse if non necessario
                                #pkt_ethernet.src = self.INFO_OTHER_AS.get(self.controller_ip)
                                nexthop_ip = path["nexthop"]
                                #print "nexthop_ip "+str(nexthop_ip)
                                prefix = path["prefix"]
                                #print pkt
                                net = ipaddr.IPNetwork(prefix)
                                if nexthop_ip.__eq__("0.0.0.0"):
                                    print "\nscelgo il primo router tcp perche' ho la destinazione direttamente connessa"
                                    pkt.get_protocol(ethernet.ethernet).dst = self.router_mac1
                                    self._send_packet(datapath, 3, pkt)
                                else:
                                    if self.INFO_OTHER_AS.get(nexthop_ip) is not None: 
                                        if port == 1:
                                            #la dst e' locale e ricevo da porta 1
                                            #print "non si installa la regola"
                                            pkt.get_protocol(ethernet.ethernet).dst = self.INFO_OTHER_AS.get(nexthop_ip)
                                            self._send_packet(datapath, 1, pkt)
                                        else:
                                            #la dst e' locale ma ricevo da porta diversa da 1
                                            parser = datapath.ofproto_parser
                                            #print "\npacchetto arriva da port non 1...si applica la best e si installa la regola nello switch con priorita' 5\n"
                                            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, ipv4_dst = (net.ip, net.netmask))                               
                                            actions = [parser.OFPActionSetNwTtl(64), parser.OFPActionSetField(eth_dst=self.INFO_OTHER_AS.get(nexthop_ip)), parser.OFPActionOutput(port = 1)]
                                            self.add_flow(datapath, 15, match, actions, 0)
                                            self._send_packet(datapath, datapath.ofproto.OFPP_TABLE, pkt)
                                    """else:
                                        #la dst non e' locale quindi bisogna inoltrare il pacchetto all'altro controller
                                        if nexthop_ip.__eq__("5.0.0.3") or nexthop_ip.__eq__("5.0.0.4") or nexthop_ip.__eq__("5.0.0.1") or nexthop_ip.__eq__("5.0.0.2"):
                                            if self.controller_ip.__eq__("50.0.0.2"):
                                                #print "mando da/a of2--->of6"
                                                self._send_packet(datapath, 4, pkt)
                                            elif self.controller_ip.__eq__("50.0.0.3"):
                                                #print "mando da/a of3--->of5"
                                                self._send_packet(datapath, 5, pkt)
                                        elif nexthop_ip.__eq__("50.0.0.1") or nexthop_ip.__eq__("50.0.0.4") or nexthop_ip.__eq__("50.0.0.3") or nexthop_ip.__eq__("50.0.0.2"):
                                            if self.controller_ip.__eq__("5.0.0.1"):
                                                #print "mando da/a of5--->of3"
                                                self._send_packet(datapath, 4, pkt)
                                            elif self.controller_ip.__eq__("5.0.0.2"):
                                                #print "mando da/a of6--->of2"
                                                self._send_packet(datapath, 4, pkt)"""
                    else:
                        print "Packet drop"
                    




    def get_best(self, list_paths_prefix):
        dict_best = {}
        for paths_prefix in list_paths_prefix:
            paths = paths_prefix["paths"]
            #assumo che ogni prefix ha una sola best
            for path_elem in paths:
                best = path_elem["best"]
                if best:
                    prefix = path_elem["prefix"]
                    nexthop_ip = path_elem["nexthop"]
                    if not nexthop_ip.__eq__("0.0.0.0"):
                        mask = int(prefix.split("/")[1])
                    else:
                        #bastava 32
                        mask = 99
                    dict_best.update({mask : path_elem})
                    break
        dict_best_sorted = OrderedDict(sorted(dict_best.items()))
        specific_mask_element = dict_best_sorted.items()[dict_best_sorted.__len__()-1]
        best_path = specific_mask_element[1]
        return best_path

    def is_this_policy_matching_with_the_packet(self ,subPolicy, src_port, dst_port, src_ipv4, dst_ipv4):
        boolean = True
        fields = subPolicy.split("_and_")
        for field in fields:
            if (field.__contains__("tcp_src")):   
                if not(int(field.split("=")[1]) == src_port):
                    boolean = False
                    break
            elif (field.__contains__("tcp_dst")):
                if not (int(field.split("=")[1]) == dst_port):
                    boolean = False
                    break
            elif (field.__contains__("ipv4_src")):
                if not (is_ip1_subnet_of_ip2(src_ipv4, field.split("=")[1])):
                    boolean = False
                    break
            elif (field.__contains__("ipv4_dst")):
                #print dst_ipv4
                #print field.split("=")[1]
                if not (is_ip1_subnet_of_ip2(dst_ipv4, field.split("=")[1])):    
                    boolean = False
                    break
        return boolean

    def add_policy_to_load_on_switch(self, dict_paths, policy_index, policies_to_load):
        list_list_dict_nexthop_policyExpanded = []
        #print "\n\n\n"
        #print dict_paths
        for key in dict_paths:
            list_dict_nexthop_policyExpanded = []
            #list_dict_nexthop_policyExpanded.append({"ipv4_dst=50.0.0.2" : "tcp_src=21_and_tcp_dst=80_and_ipv4_dst=80.0.0.0/16"})
            list_path = dict_paths.get(key)
            for path in list_path:
                prefix = path["prefix"]
                nexthop = path["nexthop"]
                expanded_policy = self.expander(self.list_rule_action[policy_index][0].split(" "), prefix)
                expanded_policy = self.check_correctness_of_match_policy(expanded_policy)
                if expanded_policy:
                    K = True
                    """Questo if controlla il nexthop, se il nexthop e' lo stesso allora si prende il prefisso meno 
                    specifico es:/8 su /16....quindi qui si considera la non ottimizzazione di nexthop"""
                    if list_dict_nexthop_policyExpanded.__len__() is not 0:
                        for dict_nexthop_policy_expanded in list_dict_nexthop_policyExpanded:
                            if (dict_nexthop_policy_expanded.keys().__contains__("ipv4_dst="+nexthop)):
                                K = False
                                sub_policy_expanded = dict_nexthop_policy_expanded.get("ipv4_dst="+nexthop).split(" ")[0]
                                match_fields = sub_policy_expanded.split("_and_")
                                prefix_in_dict = match_fields[match_fields.__len__()-1]
                                mask_in_dict = prefix_in_dict.split("=")[1].split("/")[1]
                                if int(mask_in_dict) > int(prefix.split("/")[1]):
                                    dict_nexthop_policy_expanded.update({"ipv4_dst="+nexthop : expanded_policy})
                    if K:
                        list_dict_nexthop_policyExpanded.append({"ipv4_dst="+nexthop : expanded_policy})
            list_dict_nexthop_policyExpanded = self.give_precedence_to_prefix_more_specific(list_dict_nexthop_policyExpanded)
            list_list_dict_nexthop_policyExpanded.append(list_dict_nexthop_policyExpanded)
        policies_to_load.update({policy_index : list_list_dict_nexthop_policyExpanded})
        return policies_to_load

    """Caso nexthop ottimizzato
    Una politica puo' dare origine a due regole con nexthop differenti...una regola espansa con prefix 100.0.0.0/16 
    e l'altra con 100.0.0.0/8----questo metodo serve per dare la precedenza a /16 (piu' specifico)"""
    def give_precedence_to_prefix_more_specific (self, list_dict_nexthop_policyExpanded):
        dict_mask_dict_nexthop_policyExpanded = {}
        for dict_nexthop_policyExpanded in list_dict_nexthop_policyExpanded:
            policyExpanded = dict_nexthop_policyExpanded.values()[0]
            sub_policy = policyExpanded.split(" ")[0]
            match_fields = sub_policy.split("_and_")
            prefix = match_fields[match_fields.__len__()-1]
            ip_mask = prefix.split("=")[1].split("/")
            mask = 32
            if ip_mask.__len__() == 2:
                mask = int(ip_mask[1])
            dict_mask_dict_nexthop_policyExpanded.update({mask : dict_nexthop_policyExpanded})
        return OrderedDict(sorted(dict_mask_dict_nexthop_policyExpanded.items(), reverse=True)).values()


    def getPriority(self, numberOfPolicy, positionInsidePolicy):
        #1-->100, 2-->95, 3--->90 first is number of policy and second is priority
        differencePriorityBetweenPolicy = 10000 - ((numberOfPolicy*5) - 5)
        return differencePriorityBetweenPolicy - (positionInsidePolicy - 1)

    def get_paths(self, action, list_paths_prefix):
        dict_paths = {}
        i = 0
        for act in action:
            i = i + 1
            for paths_prefix in list_paths_prefix:
                paths = paths_prefix["paths"]
                for path in paths:
                    aspath = path["aspath"]
                    if  ((aspath.__len__() > 0) and (int(act[2:]) == int(aspath[0]))):
                        if (dict_paths.keys().__contains__(i)):
                            dict_paths.get(i).append(path)
                        else:
                            dict_paths.update({i: [path]})
        return dict_paths

    def get_list_paths_prefix (self, bgpTablejson, dIP):
        list_paths_prefix = []
        for paths_prefix in bgpTablejson:
            if is_ip1_subnet_of_ip2(dIP, paths_prefix["prefix"]):
                list_paths_prefix.append(paths_prefix)
        return list_paths_prefix

    def is_ip1_subnet_of_ip2(a, b):
       """
       Returns boolean: is `a` subnet of `b`?
       """
       a = ipaddr.IPNetwork(a)
       b = ipaddr.IPNetwork(b)
       a_len = a.prefixlen
       b_len = b.prefixlen
       return a_len >= b_len and a.supernet(a_len - b_len) == b
 
    def expander(self, list_subPolicies, ip_netmask):
        expanded_policy = ""
        for subPol in list_subPolicies:
            expanded_policy += subPol+"_and_ipv4_dst="+ip_netmask+" "
        #print expanded_policy
        return expanded_policy[:-1]

    """if a policy is "tcp_src=21 and tcp_dst=80"...so subpolicies are tcp_src=21,tcp_dst=80""" 
    def check_correctness_of_match_sub_policiy(self, subPolicy_expanded):
        list_fields = subPolicy_expanded.split("_and_")
        index = self.get_first_index_containing_substring(list_fields, "ipv4_dst")
        if (index is list_fields.__len__() -1):
            return subPolicy_expanded
        else:
            dst_ipv4_ip = str(list_fields.pop(index))
            dst_ipv4_prefix = str(list_fields.pop(list_fields.__len__() - 1))
            ip = dst_ipv4_ip.split("=")[1]
            prefix = dst_ipv4_prefix.split("=")[1]
            if is_ip1_subnet_of_ip2(ip, prefix):
                subPolicy_expanded = self.create_new_expander_string(dst_ipv4_ip, list_fields)
            elif is_ip1_subnet_of_ip2(prefix, ip):
                subPolicy_expanded = self.create_new_expander_string(dst_ipv4_prefix, list_fields)
            else: 
                subPolicy_expanded = None
        return subPolicy_expanded

    def check_correctness_of_match_policy(self, expanded_policy):
        list_subPolicies_expanded = expanded_policy.split(" ")
        new_expanded_policy = ""
        for subPolicy_expanded in list_subPolicies_expanded:
            new_subPolicies_expanded = self.check_correctness_of_match_sub_policiy(subPolicy_expanded)
            if new_subPolicies_expanded:
                new_expanded_policy += new_subPolicies_expanded+" "
        if not new_expanded_policy.__eq__(""):
           return new_expanded_policy[:-1]
        return None

    def create_new_expander_string(self, ip_address, list_fields):
        expanded_policy = ""
        for field in list_fields:
            expanded_policy += field+"_and_"
        expanded_policy = expanded_policy+ip_address
        return expanded_policy
        
    def get_first_index_containing_substring(self, the_list, substring):
        for i, s in enumerate(the_list):
            if substring in s:
                  return i
        return -1

    def load_rule_on_switch(self, datapath, policies_to_load):
        #print policies_to_load
        for key in policies_to_load:
            list_list_dict_nexthop_policyExpanded = policies_to_load.get(key)
            positionInsidePolicy = 0
            for list_dict_nexthop_policyExpanded in list_list_dict_nexthop_policyExpanded:
                positionInsidePolicy = positionInsidePolicy + 1
                for dict_nexthop_policyExpanded in list_dict_nexthop_policyExpanded:
                    nexthop_ip = dict_nexthop_policyExpanded.keys()[0]
                    policy_expanded = dict_nexthop_policyExpanded.values()[0]
                    list_sub_policies_expanded = policy_expanded.split(" ")
                    list_dictionary = []
                    for sub_policy_expanded in list_sub_policies_expanded:
                        list_fields = sub_policy_expanded.split("_and_")
                        dictionary = {}
                        for field in list_fields:
                            f = field.split("=")
                            if field.__contains__("tcp"):
                                dictionary.update({str(f[0]):int(f[1])})
                            elif field.__contains__("ipv4"):
                                net = ipaddr.IPNetwork(f[1])
                                if f[1].split("/").__len__() == 2:
                                    dictionary.update({str(f[0]):(net.ip, net.netmask)})
                                else:
                                    dictionary.update({f[0]:net.ip})
                        list_dictionary.append(dictionary)
                    parser = datapath.ofproto_parser
                    #print "##############################################################"
                    #print key
                    priority = self.getPriority(key+1, positionInsidePolicy)
                    #print "priority="+str(priority)
                    nexthop_mac = self.INFO_OTHER_AS.get(str(nexthop_ip).split("=")[1])
                    #print str(nexthop_ip)+" "+str(nexthop_mac)
                    #print list_dictionary
                    for dictionary in list_dictionary:
                        #print dictionary
                        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=6, **dictionary) 
                        actions = [parser.OFPActionSetField(eth_dst=nexthop_mac), parser.OFPActionOutput(port = 1)]
                        self.add_flow(datapath, priority, match, actions, 0)


    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        my_mac = datapath.ports.get(port).hw_addr
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype = pkt_ethernet.ethertype,
                                           dst = pkt_ethernet.src,
                                           src = my_mac))
        pkt.add_protocol(arp.arp(opcode = arp.ARP_REPLY,
                                 src_mac = my_mac,
                                 src_ip = pkt_arp.dst_ip,
                                 dst_mac = pkt_arp.src_mac,
                                 dst_ip = pkt_arp.src_ip))
        #print pkt.get_protocol(arp.arp)
        self._send_packet(datapath, port, pkt)

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):
        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                           dst=pkt_ethernet.src,
                                           src=self.controller_mac))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                   src=self.controller_ip,
                                   proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                   code=icmp.ICMP_ECHO_REPLY_CODE,
                                   csum=0,
                                   data=pkt_icmp.data))
        self._send_packet(datapath, port, pkt)

    def add_flow(self, datapath, priority, match, actions, tableID):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath,table_id=tableID, priority=priority,match=match,instructions=inst)
        datapath.send_msg(mod)
        #print 'Installed rulee: ', mod

    """def add_flow_third_table(self, datapath, priority, match, actions, tableID, value, mask):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                parser.OFPInstructionWriteMetadata(value, mask)]
        mod = parser.OFPFlowMod(datapath=datapath,table_id=tableID, priority=priority,match=match,instructions=inst)
        datapath.send_msg(mod)
        print 'Installed rulee: ', mod"""

    #If I use add_flow (above) with go to, it doesn't work, so I have defined this new add_flow_for_goto
    def add_flow_for_goto(self, datapath, priority, match, actions, tableID):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath,table_id=tableID, priority=priority,match=match,instructions=actions)
        datapath.send_msg(mod)
        #print 'Installed rulee: ', mod

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


#============================================DEFLECTION=========================================================#
    #di questi metodi sotto...dal codice attuale viene utilizzato get_BGP_table....quindi in caso si vuole definire 
    #un get_BGP_table in maniera differente si deve definire un altro metodo lasciando get_BGP_table inalterato
    def get_BGP_table(self):
        X = True
        while self.RyuBGPSpeaker.speaker is None:
            if X:
                print "Attendi la formazione della tabella BGP"
                X = False
            pass
        bgpTableString = self.RyuBGPSpeaker.speaker.rib_get('ipv4','json')
        bgpTablejson = json.loads(bgpTableString)
        """Ritorno formato Json della tabella BGP...maggiori informazioni sulla tabella bgp si possono ottenere
        sostituendo il primo parametro di rib_get...esempio: mettendo rib_get('all','json') si hanno tutte le info sulla
        tabella----e' possibile ottenere la tabella bgp anche in formato 'cli' 
        Riporto il link in cui trovi queste info su rib_get http://ryu.readthedocs.io/en/latest/library_bgp_speaker_ref.html
        ps. rib_get ritorna una stringa che si trova nel formato specificato...sopra bgpTableString e' una string della tabella
        in formato json, dopo la converto in formato json vero e proprio"""
        return bgpTablejson

    def set_packet(self, packet):
        self.packet = packet

    def get_packet(self):
        if self.packet:
            return self.packet
        else: 
            print "Pacchetto None"

    def set_network(self, network):
        self.network = network

    def get_network(self):
        if self.network:
            return self.network
        else: 
            print "Network None"

    def get_deflection(self):
        bgpTablejson = self.get_BGP_table()
        pkt = self.get_packet()

        network = self.get_network()
        #print 'Switch %s ID!' % hex(network.id)
        #print 'Switch information:', network.ports
        #ToDo
        """A seconda di quello che si vuole fare Deflection puo' essere un oggetto oppure un metodo"""
    #=====================================================================================================#
