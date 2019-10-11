# Name:Hamid Abdul
# ID: 114734769
import json # For HTTP messages
from ryu.base import app_manager #the base Ryu class
from ryu.controller import ofp_event # OpenFlow events
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER # The dispatchers to handle the events
from ryu.controller.handler import set_ev_cls #The decorator to define a function for handlers
from ryu.ofproto import ofproto_v1_3 #OpenFlow v1.3 protocol
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet #To extract ethernet header
from ryu.lib.packet import ether_types #Types of ethernet packets

from webob import Response  #To respond to the web requests
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import dpid as dpid_lib    #To match the format of dpid

NetworkController_Name = 'Network_Controller'  #The name of controller class instance to be used by REST class

#The class that implements the control plane
class NetworkController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #Set the OpenFlow version of the class
    _CONTEXTS = {'wsgi': WSGIApplication}   #Add WSGI to the context of the application

    def __init__(self, *args, **kwargs):
        super(NetworkController, self).__init__(*args, **kwargs)  #Initialize the class as subclass of app_manager
        self.mac_to_port = {} #Dictionary to learn the port of a switch where a host is located
        self.switches = {} #Dictionary to store the datapath of each switch with dpid as key {ID:datapath}
        self.meter_ids = {'xx:xx:xx:xx':0} #Dictionary to create and store unique meter IDs for each host {Mac:Id}
        wsgi = kwargs['wsgi']   #An instance of WSGI server
        wsgi.register(RestHandler, {NetworkController_Name: self})   #Register the class with the REST class.

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev): #Defining the function to handle switch feature event
        datapath = ev.msg.datapath  #Get the datapath i.e. the switch that raised this event
        ofproto = datapath.ofproto  #Get the OF protocol of the datapath
        parser = datapath.ofproto_parser    #Get the parser to parse the OpenFlow message
        self.switches[datapath.id] = datapath   #Store the datapath of the switch
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Function to create and send flow entries to the switch
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,   #List of instructions for the switch
                                             actions)]                      #consists of the list of actions
        if buffer_id:   #If the packet was buffered at the switch
        #OFPFlowMod is used to add or modify an OpenFlow entry
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod) #Send the message to the switch. The message consists of entries to add to the table

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):   #Defining function that handles any incoming packets at the switch
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']  #The physical ort at which the switch received this packet

        pkt = packet.Packet(msg.data)   #Extract the packet from the OpenFlow message
        eth = pkt.get_protocols(ethernet.ethernet)[0]   #Get the Ethernet header

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst   #Destination MAC address of the packet
        src = eth.src   #Source MAC address of the packet

        dpid = datapath.id  #The datapath identifier of the switch. Unique for each switch
        self.mac_to_port.setdefault(dpid, {})   #Create a nested dictionary for each switch

        # learn a mac address to avoid FLOOD next time.
        if in_port < 100000:    #To avoid UserSwitch giving wrong ports (ocasionally)
            self.mac_to_port[dpid][src] = in_port   #Learn the port at which this mac address is located

        if dst in self.mac_to_port[dpid]:   #If the controller knows the port at which the destination is located
            out_port = self.mac_to_port[dpid][dst]  #Then set the output port for the packet
        else:
            out_port = ofproto.OFPP_FLOOD   #If not then flood the packet by setting the out_port to FLOOD

        # The action for the switch will be to forward the packet at the chosen out_port
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:  #If the location i.e. out_port of the dst is known
            #The match field is what the switch will match for future incoming packets
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id i.e. the packet is buffered at switch, if yes avoid to send both
            # flow_mod & packet_out
            # call add_flow to send a flow entry to the switch
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        # Data is the packet that came from the switch
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        # OFPPacketOut does not add an entry but tells the switch to take the required actions
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)  #Send the message to the switch

    #Network function to block flows at a switch based on an ACL entry
    # Takes the ACL entry and datapath instance (not id) as parameter and returns success or error message (str)
    def block_flow(self, datapath, ACL_Entry):
        priority=3  #Priotiy for the flow is 3. Higher than meters but lower than port block
        return 'Succesfully blocked flows. '

    #Network function to unblock flows at a switch based on an ACL entry  i.e. remove the matching OpenFlow entry
    # Takes the ACL entry and datapath instance (not id) as parameter and returns success or error message (str)
    def unblock_flow(self, datapath, ACL_Entry):
        return 'Succesfully removed ACL Entry. '


    #Network function to block a protocol at a switch based on the protocol name
    # Takes the protocol name and datapath instance (not id) as parameter and returns success or error message (str)
    def block_port(self, datapath, Proto):
        priority=4 # Priority for flows is 4. Higher than block flows and meters.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        tcp_protocols={"http":80,"ftp":21,"ssh":22,"telnet":23}
        udp_protocols={"dhcp":67}
        match=parser.OFPMatch() 
        # print "proto",Proto
        if Proto in tcp_protocols:
            pro = tcp_protocols[Proto]
            ip_proto = 6
            match = parser.OFPMatch(eth_type=0x0800,ip_proto=ip_proto, tcp_dst=pro) 
        elif Proto in udp_protocols:
            pro = udp_protocols[Proto]
            in_port=17
            match = parser.OFPMatch(eth_type=0x0800,ip_proto=ip_proto, udp_dst=pro) 

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        

        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        mod = parser.OFPFlowMod(datapath=datapath,command=ofproto.OFPFC_ADD,cookie=0, priority=priority,
                                    match=match, instructions=[])
        datapath.send_msg(mod)
        return 'Succesfully block'                   

    #Network function to unblock a protocol at a switch based on the protocol name  i.e. remove the matching OpenFlow entry
    # Takes the protocol name and datapath instance (not id) as parameter and returns success or error message (str)
    def unblock_port(self, datapath, Proto):

        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            tcp_protocols={"http":80,"ftp":21,"ssh":22,"telnet":23}
            udp_protocols={"dhcp":67}
            if Proto in tcp_protocols:
                pro = tcp_protocols[Proto]
                ip_proto = 6
                match = parser.OFPMatch(eth_type=0x0800,ip_proto=ip_proto, tcp_dst=pro) 
            elif Proto in udp_protocols:
                pro = udp_protocols[Proto]
                in_port=17
                match = parser.OFPMatch(eth_type=0x0800,ip_proto=ip_proto, udp_dst=pro) 

            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                              ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
            mod = parser.OFPFlowMod(datapath=datapath,command=ofproto.OFPMC_DELETE,cookie=0, out_group=ofproto.OFPG_ANY,out_port=ofproto.OFPP_ANY,priority=priority,
                                        match=match, instructions=[])
            datapath.send_msg(mod)

        except:
            return 'Error unblocking protocol. Check the format of ACL Entry. '

    #Network function to install a meter at a switch for a host
    # Takes the datapath instance (not id),host MAC address and limit rate as parameter and returns success or error message (str)
    def install_meter(self, datapath,eth_dst,rate):
        priority = 2    #Priority for OpenFlow entry is set to 2. Higher than forwarding entries but lower than firewall entries
        return 'Meter installed successfully. '

    #Network function to remove a meter entry from a switch for a host
    # Takes the datapath instance (not id),host MAC address and limit rate as parameter and returns success or error message (str)
    def remove_meter(self, datapath,eth_dst,rate):
        return 'Meter removed successfully. '

class RestHandler(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RestHandler, self).__init__(req, link, data, **config)
        self.NetworkController_Instance = data[NetworkController_Name]

    #Event generated when the GET method is called on the given URL
    @route('ListMacTable', '/{dpid}/mactable', methods=['GET'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):    #Function to handle event
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in self.NetworkController_Instance.mac_to_port:
            body=json.dumps('Switch does not exist.')
            return Response(status=404,content_type='application/json', body=body)

        # Get the MAC table from the NetworkController_Instance and send it as a response
        # to the request
        mac_table = self.NetworkController_Instance.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)

    #Event generated when the PUT method is called on /{dpid}/addmeter
    @route('InstallMeter', '/{dpid}/addmeter', methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def _install_meter(self, req, **kwargs):
        '''Add your solution here'''
        simple_switch = self.NetworkController_Instance #Instance of the controller class
        dpid = dpid_lib.str_to_dpid(kwargs['dpid']) #Get dpid in the correct format
        d_tapath=eval(req.body)
        # dpid =d_tapath['dpid']
        # print "datapath", dpid
        datapath = self.NetworkController_Instance.switches[int(dpid)]
        # print "datapath", datapath
        d_add = d_tapath['mac']# get mac address
        rate = d_tapath['rate']# get rate

        try:
            new_entry = req.json
        except:
            body=json.dumps('Could not load entry.')
            
            return Response(status=400,content_type='application/json', body=body)

        if dpid not in simple_switch.switches:
            body=json.dumps('Switch does not exist.')
            return Response(status=404,content_type='application/json', body=body)

        try:
            # Call the network function which takes dpid and MAC table entry
            # mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            #Create the body of the response using the returned mac table
            # body = json.dumps(mac_table)
            # Send the response to the requesting application
            body = simple_switch.install_meter(datapath,d_add,rate)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            # print " ", e
            body=json.dumps(e)
            return Response(status=500,content_type='application/json', body=body)

    #Event generated when the PUT method is called on /{dpid}/removemeter
    @route('RemoveMeter', '/{dpid}/removemeter', methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def _remove_meter(self, req, **kwargs):
        '''Add your solution here'''

        simple_switch = self.NetworkController_Instance #Instance of the controller class
        dpid = dpid_lib.str_to_dpid(kwargs['dpid']) #Get dpid in the correct format
        d_tapath=eval(req.body)
        # dpid =d_tapath['dpid']
        datapath = self.NetworkController_Instance.switches[int(dpid)]
        d_add = d_tapath['mac']# get mac address
        rate = d_tapath['rate']# get rate

        try:
            new_entry = req.json
        except:
            body=json.dumps('Could not load entry.')
            
            return Response(status=400,content_type='application/json', body=body)

        if dpid not in simple_switch.switches:
            body=json.dumps('Switch does not exist.')
            return Response(status=404,content_type='application/json', body=body)

        try:
            # Call the network function which takes dpid and MAC table entry
            # mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            #Create the body of the response using the returned mac table
            # body = json.dumps(mac_table)
            # Send the response to the requesting application
            body = simple_switch.remove_meter(datapath,d_add,rate)
            return Response(content_type='application/json', body=body)
        except Exception as e:
            body=json.dumps(e)
            return Response(status=500,content_type='application/json', body=body)

    #Event generated when the PUT method is called on /{dpid}/blockflow
    @route('BlockFlow', '/blockflow', methods=['PUT'])
    def _block_flow(self, req, **kwargs):
        '''Add your solution here'''
        datapath=eval(req.body)
        dpid =datapath['dpid']
        pro=datapath['protocol']
        datapath = self.NetworkController_Instance.switches[int(dpid)]
        self.NetworkController_Instance.block_flow(datapath,pro)
        return

    #Event generated when the PUT method is called on /{dpid}/unblockflow
    @route('UnblockFlow', '/unblockflow', methods=['PUT'])
    def _unblock_flow(self, req, **kwargs):
        '''Add your solution here'''
        datapath=eval(req.body)
        dpid =datapath['dpid']
        pro=datapath['protocol']
        datapath = self.NetworkController_Instance.switches[int(dpid)]
        self.NetworkController_Instance.unblock_flow(datapath,pro)
        return

    #Event generated when the PUT method is called on /{dpid}/blockport
    @route('BlockPort', '/blockport', methods=['PUT'])
    def _block_port(self, req, **kwargs):
        '''Add your solution here'''

        datapath=eval(req.body)
        dpid =datapath['dpid']
        pro=datapath['protocol']
        datapath = self.NetworkController_Instance.switches[int(dpid)]
        self.NetworkController_Instance.block_port(datapath,pro)
        return

    #Event generated when the PUT method is called on /{dpid}/unblockport
    @route('UnblockPort', '/unblockport', methods=['PUT'])
    def _unblock_port(self, req, **kwargs):
        '''Add your solution here'''
        datapath=eval(req.body)
        dpid =datapath['dpid']
        pro=datapath['protocol']
        datapath = self.NetworkController_Instance.switches[int(dpid)]
        self.NetworkController_Instance.unblock_port(datapath,pro)
        return
