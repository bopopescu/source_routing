"""
Author: shengrulee
Create data: 2016.3.24
"""

from pox.core import core

from SocketServer import TCPServer, StreamRequestHandler, ThreadingTCPServer, _eintr_retry
from socket import *
import select
import threading
from __init__ import *



#log = core.getLogger()

ADDR = ('192.168.109.120', 6655)
BUFSIZE = 1024


class ThreadingInterDomainServer(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.name = 'ThreadingInterDomainServer'
        self.InterDomainSerSock = None
        self.createSerSock()

    def run(self):
        apply(self.createSerSock())

    def createSerSock(self):
        self.InterDomainSerSock = socket(AF_INET, SOCK_STREAM)
        self.InterDomainSerSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.InterDomainSerSock.bind(ADDR)
        self.InterDomainSerSock.listen(5)

        try:
            while 1:
                print 'Server: waiting for connection from other controller...'
                conn, addr = self.InterDomainSerSock.accept()
                print 'Server: connected to', addr
                conn.send('Server: Hello!')

                while 1:
                    data = conn.recv(BUFSIZE)
                    if not data:
                        break
                    # raise the event
                    #core.InterDomainConnection.raiseEvent(InterDomainRequest, data, addr)
                    print data

                conn.close()

        except (EOFError, KeyboardInterrupt):
            self.InterDomainSerSock.close()

if __name__ == '__main__':
    IDS = ThreadingInterDomainServer()





