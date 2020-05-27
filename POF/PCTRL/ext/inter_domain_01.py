"""
Author: shengrulee
Date: 2015.12.28

This file is to realize the communication between two POF controllers.
"""

from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event
import pox.openflow.libpof_02 as of
from pox.core import core

import json
import socket
import threading
import errno

HOST = '192.168.109.120'
PORT = 6655
ADDR = (HOST, PORT)
BUFSIZE = 1024

neighbor_controllers = ['192.168.109.231', '192.168.1.109']

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


class InterDomainRequest(Event):
    def __init__(self, data, addr):
        Event.__init__(self)
        self.data = data
        self.addr = addr


class InterDomainReply(Event):
    def __init__(self, data, addr):
        Event.__init__(self)
        self.data = data
        self.addr = addr


def inter_domain_client(controller_addr):
    socket_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    while 1:
        try:
            socket_client.connect((controller_addr, PORT))

            print "Client: connected to controller at %s" % controller_addr

            while 1:
                data = socket_client.recv(BUFSIZE)
                if not data:
                    break
                socket_client.send(json.dumps(protocol))
                print data

            #socket_client.close()

        except socket.error as serr:
            '''
            if serr.errno != errno.ECONNREFUSED and serr.errno != errno.EBADF:
                raise serr    # Not the error we are looking for, re-raise the error
            else:
                continue    # Yes, connection refused
            '''
            continue


def inter_domain_server():
    socket_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socket_server.bind(ADDR)
    socket_server.listen(5)

    try:
        while 1:
            print 'Server: waiting for connection from other controller...'
            conn, addr = socket_server.accept()
            print 'Server: connected to', addr
            conn.send('Server: Hello!')

            while 1:
                data = conn.recv(BUFSIZE)
                if not data:
                    break
                # raise the event
                core.InterDomainConnection.raiseEvent(InterDomainRequest, data, addr)
                print data

            conn.close()

    except (EOFError, KeyboardInterrupt):
        socket_server.close()


class MyThread(threading.Thread): # a self define thread type
    def __init__(self, func, args, name=''):
        threading.Thread.__init__(self)
        self.name = name
        self.func = func
        self.args = args

    def run(self):
        self.res = apply(self.func, self.args)

    def getResult(self):
        return self.res


class InterDomainConnection(EventMixin):

    _eventMixin_events = set([
        InterDomainReply,
        InterDomainRequest,
    ])

    def __init__(self):
        #core.openflow.addListeners(self)
        self.addListeners(self)

        # create and start the server thread
        self.server_thread = MyThread(inter_domain_server, [], "InterDomainTCPServer")
        self.server_thread.setDaemon(True)
        self.server_thread.start()

        # create and start the client thread
        self.client_threads_list = []
        for i in range(len(neighbor_controllers)):
            client_thread = MyThread(inter_domain_client, [neighbor_controllers[i]], "InterDomainTCPClient"+str(i))
            client_thread.setDaemon(True)
            self.client_threads_list.append(client_thread)

        for client_thread in self.client_threads_list:
            client_thread.start()

        '''
        for client_thread in self.client_threads_list:
            client_thread.join()

        '''


    def _handle_InterDomainRequest(self, event):
        print "got the inter domain request"
        print event.data


def launch():
    core.registerNew(InterDomainConnection)
