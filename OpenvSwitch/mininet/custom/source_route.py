"""Custom topology example

Two directly connected switches plus a host for each switch:

   host --- switch --- switch --- host

Adding the 'topos' dict with a key/value pair to generate our newly defined
topology enables one to pass in '--topo=mytopo' from the command line.
"""

from mininet.topo import Topo

class MyTopo( Topo ):
    "Simple topology example."

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        hostlist = [self.addHost('h%d' % i, mac="00:00:00:00:00:0%d" % i) for i in range(1, 10)]

        host10 = self.addHost('h10', mac="00:00:00:00:00:0A")
        host11 = self.addHost('h11', mac="00:00:00:00:00:0B")
        # add switch
        switchlist = [self.addSwitch('s%d' % i) for i in range(1, 6)]
        s6 = self.addSwitch('s6')
        s7 = self.addSwitch('s7')
        # add links
        self.addLink(hostlist[0], switchlist[0])
        lastswitch = None
        for switch in switchlist:
            if lastswitch:
                self.addLink(lastswitch, switch)
            lastswitch=switch
        self.addLink(switchlist[2], s6)
        self.addLink(switchlist[3], s7)
        self.addLink(s6, s7)
        for host in hostlist[1:9]:
            self.addLink(host, switchlist[4])
#        for host in hostlist[5:8]:
#            self.addLink(host, switchlist[3])
 #        self.addLink(hostlist[8], s7)
        self.addLink(host10, switchlist[4])
        self.addLink(host11, switchlist[4])


topos = { 'mytopo': ( lambda: MyTopo() ) }
