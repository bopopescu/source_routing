'''
Author: shengrulee
Create data: 2016.4.12
'''

from pox.core import core
from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event

import struct
import __init__

log = core.getLogger()

class InterDomainProcessor(EventMixin):

    def __init__(self):
        core.openflow.addListeners(self)
        core.InterDomainConnection.addListeners(self)

    def _handle_InterDomainRequest(self, event):
        msg = struct.unpack((event.data))
        log.info("got the inter domain request: %s" % event.data)
        #event.connection.send('hello')



def launch():
    core.registerNew(InterDomainProcessor)
