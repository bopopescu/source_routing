"""
author: shengrulee
data: 2016.3.28
"""

class DomainAbstractTopo(object):

    def __init__(self):
        self.ipToPort = {}

    def writeTopo(self, ip, outport):
        self.ipToPort[ip] = outport





