# Part 3 of UWCSE's Project 3
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr
import pox.lib.packet as pkt

log = core.getLogger()

#statically allocate a routing table for hosts
#MACs used in only in part 4
IPS = {
  "h10" : ("10.0.1.10", '00:00:00:00:00:01'),
  "h20" : ("10.0.2.20", '00:00:00:00:00:02'),
  "h30" : ("10.0.3.30", '00:00:00:00:00:03'),
  "serv1" : ("10.0.4.10", '00:00:00:00:00:04'),
  "hnotrust" : ("172.16.10.100", '00:00:00:00:00:05'),
}

class Part3Controller (object):
  """
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    print (connection.dpid)
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection
    self.IPTo = {
      # '10.0.1.10': [],
      # '10.0.2.20': [],
      # '10.0.3.30': [],
      # '10.0.4.10': [],
      # '172.16.10.100': []
    }
    # This binds our PacketIn event listener
    connection.addListeners(self)
    #use the dpid to figure out what switch is being created
    if (connection.dpid == 1):
      self.s1_setup()
    elif (connection.dpid == 2):
      self.s2_setup()
    elif (connection.dpid == 3):
      self.s3_setup()
    elif (connection.dpid == 21):
      self.cores21_setup()
    elif (connection.dpid == 31):
      self.dcs31_setup()
    else:
      print ("UNKNOWN SWITCH")
      exit(1)

  def s1_setup(self):
    #put switch 1 rules here
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    msg.match = match
    msg.priority = 3000
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)
    pass

  def s2_setup(self):
    #put switch 2 rules here
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    msg.match = match
    msg.priority = 3000
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)
    pass

  def s3_setup(self):
    #put switch 3 rules here
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    msg.match = match
    msg.priority = 3000
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)
    pass

  def cores21_setup(self):
    #put core switch rules here
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    match.nw_src = IPS["hnotrust"][0]
    match.nw_proto = pkt.ipv4.ICMP_PROTOCOL
    match.dl_type = pkt.ethernet.IP_TYPE
    msg.match = match
    msg.priority = 3000
    self.connection.send(msg)
    pass

  def dcs31_setup(self):
    #put datacenter switch rules here
    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    match.nw_src = IPS["hnotrust"][0]
    match.dl_type = pkt.ethernet.IP_TYPE
    msg.match = match
    msg.priority = 3000
    self.connection.send(msg)

    msg = of.ofp_flow_mod()
    match = of.ofp_match()
    msg.match = match
    msg.priority = 3000
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    self.connection.send(msg)
    pass

  #used in part 4 to handle individual ARP packets
  #not needed for part 3 (USE RULES!)
  #causes the switch to output packet_in on out_port
  def resend_packet(self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)
    self.connection.send(msg)

  def _handle_PacketIn (self, event):
    """
    Packets not handled by the router rules will be
    forwarded to this method to be handled by the controller
    """
    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return
    print(pkt.ethernet.IP_TYPE)
    packet_in = event.ofp # The actual ofp_packet_in message.
    # print(dir(packet))
    if (self.connection.dpid == 21):
      # if packet.next.srcip not in self.IPTo :
      #   self.ITTo[packet.next.srcip] = {}
      if packet.type == packet.ARP_TYPE:
        self.IPTo[packet.next.protosrc] = (packet_in.in_port, packet.src)
        a = packet.next
        r = arp()
        r.hwtype = a.hwtype
        r.prototype = a.prototype
        r.hwlen = a.hwlen
        r.protolen = a.protolen
        r.opcode = arp.REPLY
        r.hwdst = a.hwsrc
        r.protodst = a.protosrc
        r.protosrc = a.protodst
        r.hwsrc = EthAddr("00:00:00:00:00:00")
        e = ethernet(type=packet.type, src=EthAddr("00:00:00:00:00:00"),
                      dst=a.hwsrc)
        e.set_payload(r)
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port =
                                                of.OFPP_IN_PORT))
        msg.in_port = packet_in.in_port
        event.connection.send(msg)

        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.dl_type = 0x0800
        match.nw_dst = packet.next.protosrc
        msg.match = match
        msg.priority = 3000
        msg.actions.append(of.ofp_action_output(port = self.IPTo[packet.next.protosrc][0]))
        self.connection.send(msg)

        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.dl_type = 0x0806
        match.nw_dst = packet.next.protosrc
        msg.match = match
        msg.priority = 3000
        msg.actions.append(of.ofp_action_output(port = self.IPTo[packet.next.protosrc][0]))
        self.connection.send(msg)
      else:
        print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump() + "PORT:: " + str(packet_in.in_port))
    else:
      print ("Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump() + "PORT:: " + str(packet_in.in_port))


def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Part3Controller(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
