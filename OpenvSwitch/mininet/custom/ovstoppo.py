from mininet.topo import Topo


class MyTopo(Topo):

    def __init__(self):
        # initilaize topology
        Topo.__init__(self)

        # add hosts
        hostlist = [self.addHost('h%d'%i,mac="00:00:00:00:00:0%d"%i)for i in range(1,10)]
        host10 = self.addHost('h10',mac="00:00:00:00:00:0A")
        host11 = self.addHost('h11', mac="00:00:00:00:00:0B")
        #add switch
        switchlist = [self.addSwitch('s%d'%i) for i in range(1,6)]
        s6=self.addSwitch('s6')
        s7=self.addSwitch('s7')
        # add links
        self.addLink(hostlist[0], switchlist[0])
        lastswitch=None
        for switch in switchlist:
            if lastswitch:
                self.addLink(lastswitch,switch)
        self.addLink(switchlist[2],s6)
        self.addLink(switchlist[3], s7)
        self.addLink(s6, s7)
        for host in hostlist[1:5]:
            self.addlinks(host,switch[4])
        for host in hostlist[5:8]:
            self.addlinks(host, switch[4])
        self.addlinks(hostlist[8], s7)
        self.addlinks(host10, s7)
        self.addlinks(host11, s7)




topos = {'mytopo': (lambda: MyTopo())}