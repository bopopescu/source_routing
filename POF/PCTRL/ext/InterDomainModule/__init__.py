'''
Author: shengrulee
Create data: 2016.3.24
'''

from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event
from pox.core import core

import json
import socket
import threading
import errno

from lib_interdomain import *

log = core.getLogger()

HOST = '192.168.109.120'
PORT = 6655
ADDR = (HOST, PORT)
BUFSIZE = 1024

neighbor_controllers = ['192.168.109.191', '192.168.1.109']

protocol = {
    'name': 'Ethernet',
    'match':{
        'DMAC': {
            'offset': 0,
            'length': 48,
        },
        'SMAC': {
            'offset': 48,
            'length': 96,
        },
        'dl_type': {
            'offset': 96,
            'length': 16,
        },
    }
}


def echo_cycle(con):
    def sayhello():
        #print "send echo_request"
        hello = struct.pack('!BHH', 1,3,4)
        con.write(hello)
        global t
        t = threading.Timer(2.0, sayhello)
        t.start()
    t = threading.Timer(2.0, sayhello)
    t.start()


def jsonToClass(msg_json):
    pass

def classToJson(msg_class):
    pass


'''
Inter-Domain events type.
'''


class InterDomainRequest(Event):
    def __init__(self, data, addr, conn):
        Event.__init__(self)
        self.data = data
        self.addr = addr
        self.connection = conn


class InterDomainReply(Event):
    def __init__(self, data, addr):
        Event.__init__(self)
        self.data = data
        self.addr = addr


class EchoRequest(Event):
    def __init__(self, data, addr):
        Event.__init__(self)
        self.data = data
        self.addr = addr


class EchoReply(Event):
    def __init__(self, data, addr):
        Event.__init__(self)
        self.data = data
        self.addr = addr

class InterDomainPacketIn(Event):
    def __init__(self, data, addr):
        Event.__init__(self)
        self.data = data
        self.addr = addr


class ClientThread(threading.Thread):

    def __init__(self, client_sock, addr, id):
        threading.Thread.__init__(self)
        self.name = 'InterDomainClient'
        self.sock = client_sock
        self.id = id
        self.addr = addr

    def run(self):
        while 1:
            data = self.read()

        self.sock.close()
        return

    def read(self):
        msg = self.sock.recv(BUFSIZE)
        if not msg:
            return
        print "received a message : ", msg
        #self.write(msg)
        return msg

    def write(self, msg):

        self.sock.send(msg)

    def __str__(self, prefix = '  '):
        outstr = '\n'
        outstr += prefix + 'name: ' + self.name + '\n'
        outstr += prefix + 'id: ' + str(self.id) + '\n'
        outstr += prefix + 'address: %s:%s' % (self.addr[0], self.addr[1])
        return outstr


class InterDomainServer(object):

    def __init__(self):
        self.name = 'InterDomainServer'
        self.connections_thread_list = []
        self.connections_thread_dict = {}

        self.createSockSer()

        self.client_id_init = 0

    def createSockSer(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(ADDR)
        self.sock.listen(5)

    def run(self):

        # a new thread for accepting new incoming client connections
        log.info('Inter-domain server start to run')
        server_thread = threading.Thread(target = self._run)
        server_thread.setDaemon(True)
        server_thread.start()

    def _run(self):

        # infinite loop for accepting new incoming connections
        while 1:
            conn, addr = self.sock.accept()
            client_thread = ClientThread(conn, addr, self.client_id_init)

            #debug
            log.info(client_thread)

            self.client_id_init += 1
            self.connections_thread_list.append(client_thread)
            self.connections_thread_dict[addr[0]] = client_thread
            client_thread.setDaemon(True)
            client_thread.start()

            # send hello message periodically
            echo_cycle(client_thread)

            # for each_thread in self.connections_thread_list:
            #     if not each_thread.isAlive():
            #         self.connections_thread_list.remove(each_thread)
            #         each_thread.join()
            #
            #     else:
            #         print 'aaaa'

    # write a message to a client
    def write(self, addr, msg):
        # print 'herererere'
        # print len(self.connections_thread_list)
        if addr in self.connections_thread_dict.keys():
            client_thread = self.connections_thread_dict[addr]
            if msg:
                client_thread.write(msg)
                return True
            else:
                log.info('Send message is empty')
                return False
        else:
            log.info('There is no inter-domain client at %s' % addr)


        # for client_thread in self.connections_thread_list:
        #     print 'hhhhhhhhh'
        #     print client_thread.addr
        #     print addr
        #     if client_thread.addr[0] == addr:
        #         print 'herer33333'
        #         if msg:
        #             print 'here2'
        #             client_thread.write(msg)
        #             return True
        #         else:
        #             log.info('Send message is empty')
        #             return False


class InterDomainClient(object):

    def __init__(self, addr, port):
        self.sock = None
        self.server_addr = addr
        self.server_port = port

    def run(self):
        client_thread = threading.Thread(target=self._run,)
        client_thread.setDaemon(True)
        client_thread.start()

    def _run(self):

        while 1:

            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect((self.server_addr, self.server_port))
                log.info('[InterDomainClient] Connect to server successfully.')

                while 1:

                    data = self.read()
                    if data:
                        # log.info('Received data %s' % data)
                        core.InterDomainConnection.raiseEvent(InterDomainRequest, data, self.server_addr, self.sock)
                    else:
                        self.sock.close()
                        break

            except socket.error, e:
                pass
                #print e


    def read(self):
        # try:
        #     data = self.sock.recv(BUFSIZE)
        #     return data
        # except socket.error:
        #     self.sock.close()
        data = self.sock.recv(BUFSIZE)
        return data

    def write(self, msg):
        t = threading.Timer(5, self.sock.send, args = [msg])
        t.start()


class InterDomainConnection(EventMixin):

    _eventMixin_events = set([
        InterDomainReply,
        InterDomainRequest,
    ])

    def __init__(self):
        core.openflow.addListeners(self)
        self.addListeners(self)
        self.server = InterDomainServer()
        self.client = InterDomainClient(neighbor_controllers[0], 6655)
        self.run()

    def run(self):
        self.server.run()

        #t = threading.Timer(2.0, self.server.write,args = [neighbor_controllers[0], 'he'])
        #t.start()

        self.client.run()
        #client.write('hello')

    # def _handle_InterDomainRequest(self, event):
    #     log.info("got the inter domain request")
    #     self.client.write('hello')
    #     print 'in __init__', event.data



def launch():
    core.registerNew(InterDomainConnection)