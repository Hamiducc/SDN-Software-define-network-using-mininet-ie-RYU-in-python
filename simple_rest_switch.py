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

app_instance_name = 'simple_switch_api_app' #The name of controller class instance to be used by REST class


#The class that implements the control plane
class SimpleSwitch13(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #Set the OpenFlow version of the class
    _CONTEXTS = {'wsgi': WSGIApplication}   #Add WSGI to the context of the application

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs) #Initialize the class as subclass of app_manager
        self.mac_to_port = {} #Dictionary to learn the port of a switch where a host is located
        self.switches = {}  #Dictionary to store the datapath of each switch with dpid as key {ID:datapath}
        wsgi = kwargs['wsgi']   #An instance of WSGI server
        wsgi.register(RestHandler, {app_instance_name: self})   #Register the class with the REST class.


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev): #Defining the function to handle switch feature event
        datapath = ev.msg.datapath  #Get the datapath i.e. the switch that raised this event
        ofproto = datapath.ofproto  #Get the OF protocol of the datapath
        parser = datapath.ofproto_parser    #Get the parser to parse the OpenFlow message
        self.switches[datapath.id] = datapath   #Store the datapath of the switch
        self.mac_to_port.setdefault(datapath.id, {})    #Create an entry for the switch in the MAC table
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

    # The network function to call from REST. Takes dpid and a MAC table entry as parameters.
    # Updates the MAC table with the information in entry i.e. mac and in_port and installs
    # OpenFlow entries in the switch if possible.
    def set_mac_to_port(self, dpid, entry):
        mac_table = self.mac_to_port.setdefault(dpid, {})   #Get the MAC table of the switch
        datapath = self.switches.get(dpid)  #Get the datapath of the switch

        entry_port = entry['port']
        entry_mac = entry['mac']

        if datapath is not None:    #If datapath of the switch retrieved
            parser = datapath.ofproto_parser
            if entry_port not in mac_table.values():    #If a new port is learned
                # Add OpenFlow entries for all the exisiting entries in the table
                for mac, port in mac_table.items():

                    # from known device to new device
                    actions = [parser.OFPActionOutput(entry_port)]
                    match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                    self.add_flow(datapath, 1, match, actions)

                    # from new device to known device
                    actions = [parser.OFPActionOutput(port)]
                    match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                    self.add_flow(datapath, 1, match, actions)

                mac_table.update({entry_mac: entry_port})
        return mac_table    #Update the MAC table and return the updated table.

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev): #Defining function that handles any incoming packets at the switch

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto, parser = datapath.ofproto,datapath.ofproto_parser
        in_port = msg.match['in_port'] #The physical ort at which the switch received this packet

        pkt = packet.Packet(msg.data)   #Extract the packet from the OpenFlow message
        eth = pkt.get_protocols(ethernet.ethernet)[0]   #Get the Ethernet header

        if eth.ethertype != ether_types.ETH_TYPE_ARP:
            # Only flood ARPs
            return

        self.logger.info("Flooding ARPs from dpid: %s port: %s src: %s", dpid, in_port, eth.src)

        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]  #Action is to flood the packet

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data #Add the packet data to the message

        # Create the message to flood
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)

        datapath.send_msg(out)  #Send the message to the switch

#The class that implements and defines the REST API
class RestHandler(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(RestHandler, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[app_instance_name]    #Name of controller class

    #Event generated when the GET method is called on the given URL
    @route('simpleswitch', '/mactable/{dpid}', methods=['GET'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):    #Function to handle event
        simple_switch = self.simple_switch_app  #Instance of the controller class
        dpid = dpid_lib.str_to_dpid(kwargs['dpid'])

        if dpid not in simple_switch.mac_to_port:
            body=json.dumps('Switch does not exist.')
            return Response(status=404,content_type='application/json', body=body)

        # Get the MAC table from the simple_switch instance and send it as a response
        # to the request
        mac_table = simple_switch.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', body=body)

    #Event generated when the PUT method is called on the given URL
    @route('simpleswitch', '/mactable/{dpid}', methods=['PUT'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def put_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app #Instance of the controller class
        dpid = dpid_lib.str_to_dpid(kwargs['dpid']) #Get dpid in the correct format
        try:
            new_entry = req.json
        except:
            body=json.dumps('Could not load entry.')
            return Response(status=400,content_type='application/json', body=body)

        if dpid not in simple_switch.mac_to_port:
            body=json.dumps('Switch does not exist.')
            return Response(status=404,content_type='application/json', body=body)

        try:
            # Call the network function which takes dpid and MAC table entry
            mac_table = simple_switch.set_mac_to_port(dpid, new_entry)
            #Create the body of the response using the returned mac table
            body = json.dumps(mac_table)
            # Send the response to the requesting application
            return Response(content_type='application/json', body=body)
        except Exception as e:
            body=json.dumps(e)
            return Response(status=500,content_type='application/json', body=body)
