"""
Author: shengrulee
Date: 2016.1.7

This file is to realize the communication between two POF controllers.
"""

from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event
import pox.openflow.libpof_02 as of
from pox.core import core
from pox.lib.addresses import IPAddr

import json


class ForwardingTables(object):
    def __init__(self, domain_id):
        self.domain_id = domain_id
        # ip_addr: weight
        self.IPtoVPort = {IPAddr('192.168.109.191'): 500,
                          IPAddr('192.168.109.120'): 100}




class NeighbourAS(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)


def launch():
    core.registerNew(NeighbourAS)


if __name__ == '__main__':
    print IPAddr('192.168.109.211')
