'''
Created on Nov 23, 2018

@author: niubin
'''
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.node import RemoteController
from mininet.pof import POFSwitch

import sys

IPAddr = sys.argv[1]


def buildlineTopo():
    '''
    h1---s1---s2---s3---h2
    '''
    pofNet = Mininet(switch=POFSwitch, controller=RemoteController)

    # build switches
    n = 5
    switchList = [pofNet.addSwitch('s%d' % i, listenPort=6633 + i) for i in range(1, n + 1)]
    pofNet.addController('c0', controller=RemoteController, ip=IPAddr, port=6666)
    host = pofNet.addHost('h1', mac="00:00:00:00:00:01")
    pofNet.addLink(host, switchList[0])

    lastSwitch = None
    for switch in switchList:
        if lastSwitch:
            pofNet.addLink(lastSwitch, switch)
        lastSwitch = switch
    # build hosts

    hostlist = [pofNet.addHost('h%d'%i, mac="00:00:00:00:00:0%d"%i)for i in range(2,9)]
    for host in hostlist:
        pofNet.addLink(host, switchList[4])
    s6 = pofNet.addSwitch('s6',listenPort=6639)
    s7 = pofNet.addSwitch('s7',listenPort=6640)
    pofNet.addLink(switchList[2],s6)
    pofNet.addLink(switchList[3],s7)
    pofNet.addLink(s6,s7)
    host = pofNet.addHost('h9', mac="00:00:00:00:00:09")
    pofNet.addLink(host, switchList[4])
    host = pofNet.addHost('h10', mac="00:00:00:00:00:0A")
    pofNet.addLink(host, switchList[4])
    host = pofNet.addHost('h11', mac="00:00:00:00:00:0B")
    pofNet.addLink(host, switchList[4])
    # hostlist = [pofNet.addHost('h%d' % i, mac="00:00:00:00:00:0%d" % i) for i in range(6, 9)]
    # for host in hostlist:
    #     pofNet.addLink(host, switchList[3])
    # pofNet.delLinkBetween(switchList[1],switchList[2])
    # start the network
    pofNet.start()
    dumpNodeConnections(pofNet.switches)
    CLI(pofNet)
    pofNet.stop()


if __name__ == '__main__':
    cleanup()
    setLogLevel('info')
    import time
    time.sleep(1)
    buildlineTopo()



