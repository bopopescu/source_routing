'''
Created on Sept 2, 2015

@author: Cen Chen
'''

import pox
#import pox.openflow.debug
import lib_peer as peer

from pox.core import core
from pox.lib.recoco.recoco import Task
from pox.lib.recoco.recoco import Select
from pox.lib.revent.revent import Event
from pox.lib.revent.revent import EventMixin
#from pox.lib.socketcapture import CaptureSocket

#import os
import sys
#import ssl
import time
import socket
import threading
#import datetime
#import traceback
import exceptions
from errno import ECONNRESET

log = core.getLogger()

def echo_cycle(con):
    def sayhello():
        #print "send echo_request"
        con.send(peer.peer_echo_request())
        global t
        t = threading.Timer(2.0, sayhello)
        t.start()
    t = threading.Timer(2.0, sayhello)
    t.start()

# ----------------------------------------------------------
# Peer Message Unpackers
# ----------------------------------------------------------
def make_type_to_unpacker_table ():
    top = max(peer._message_type_to_class)
    r = [peer._message_type_to_class[i].unpack_new for i in range(0, top + 1)]
    return r

unpackers = make_type_to_unpacker_table()
# ----------------------------------------------------------

# ----------------------------------------------------------
# Peer Events
# ----------------------------------------------------------
class ConnectionUp (Event):
    """
    Event raised when the connection to a peer controller has been established.
    """
    def __init__ (self, connection, msg):
        Event.__init__(self)
        self.connection = connection
        self.addr = connection.addr
        self.msg = msg
# ----------------------------------------------------------

# ----------------------------------------------------------
# Peer Message Handers
# ----------------------------------------------------------
def handle_HELLO (con, msg):
    con.info('peer connected: handle_HELLO')
    msg = peer.peer_features_report()
    con.send(msg)
    
def handle_FEATURES_REPORT (con, msg):
    con.info('peer connected: handle_FEATURES_REPORT')
    echo_cycle(con)
    
def handle_ECHO_REPLY (con, msg):
    #con.msg("Got echo reply")
    #con.info('peer connected: handle_ECHO_REPLY')
    pass

def handle_ECHO_REQUEST (con, msg):
    #con.info('peer connected: handle_ECHO_REQUEST')
    reply = msg
    reply.header_type = peer.PEER_ECHO_REPLY
    con.send(reply)

handlers = []

handlerMap = {
    peer.PEER_HELLO : handle_HELLO,
    peer.PEER_FEATURES_REPORT : handle_FEATURES_REPORT,
    peer.PEER_ECHO_REPLY : handle_ECHO_REPLY,
    peer.PEER_ECHO_REQUEST : handle_ECHO_REQUEST,
}
# ----------------------------------------------------------

# ----------------------------------------------------------
# Peer Sockets
# ----------------------------------------------------------
class Connection (EventMixin):
    
    ID = 0
    
    def __init__ (self, sock):
        self.sock = sock
        self.buf = ''
        Connection.ID += 1
        self.ID = Connection.ID
        self.disconnected = False
        self.connect_time = None
        self.idle_time = time.time()
        self.addr = sock.getpeername()
        
    def msg (self, m):
        log.debug(str(self) + " " + str(m))
        
    def err (self, m):
        log.error(str(self) + " " + str(m))
        
    def info (self, m):
        log.info(str(self) + " " + str(m))
        
    def fileno (self):
        return self.sock.fileno()
    
    def close (self):
        #self.disconnect('closed')
        try:
            self.sock.close()
        except:
            pass
    
    def send (self, data):
        if self.disconnected: return
        if type(data) is not bytes:
            assert isinstance(data, peer.peer_header)
            data = data.pack()
        l = self.sock.send(data)
        if l != len(data):
            self.msg("Didn't send complete buffer.")
        
    def read (self):
        try:
            d = self.sock.recv(2048)
        except:
            return False
        if len(d) == 0:
            return False
        self.buf += d
        buf_len = len(self.buf)
        
        offset = 0
        while buf_len - offset >= 8:
            if ord(self.buf[offset]) != peer.PEER_VERSION:
                log.warning("Bad Peer version (0x%02x) on Connection %s" 
                            % (ord(self.buf[offset]), self))
                return False
            peer_type = ord(self.buf[offset+1])
            msg_length = ord(self.buf[offset+2]) << 8 | ord(self.buf[offset+3])
            #print "Connection.read() -> msg_length: ", msg_length
            
            if buf_len - offset < msg_length: break
            new_offset, msg = unpackers[peer_type](self.buf, offset)
            assert new_offset - offset == msg_length
            offset = new_offset
            
            try:
                h = handlerMap[peer_type]
                h(self, msg)
            except:
                log.exception("%s: Exception while handling OpenFlow message:\n" +
                              "%s %s", self,self,
                              ("\n" + str(self) + " ").join(str(msg).split('\n')))
                continue
            
        if offset != 0:
            self.buf = self.buf[offset:]
            
    def __str__ (self):
        return "[Con %s %i]" % (self.sock.getpeername()[0], self.sock.getpeername()[1])

class Peer_Client_Task(Task):
    def __init__(self, port = 2555, address = '0.0.0.0'):
        Task.__init__(self)
        self.port = port
        self.address = address
        self.started = False
        self.con = None
    
        core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)
        
    def _handle_GoingUpEvent(self, event):
        self.start()
        
    def start(self):
        if self.started:
            return
        self.started = True
        return super(Peer_Client_Task,self).start()
    
    def run(self):
        sockets = []
        sock_clients = [None]*len(self.address)
        #sock_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #sock_client.setblocking(0)
        #con_state = 0
        con_states = [0]*len(self.address)
        #print self.address
        
        while core.running:
            try:
                while True:
                    for i in range(len(con_states)):
                        #print 'con_states', con_states
                        if con_states[i] == 0:
                            try:
                                #con_states[i] = 1
                                peer_addr = (self.address[i], self.port)
                                
                                sock_tmp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                #sock_tmp = ssl.wrap_socket(sock_tmp)
                                #sock_tmp.setblocking(0)
                                sock_clients[i] = sock_tmp
                                sock_tmp.settimeout(1)
                                sock_tmp.connect(peer_addr)
                                con_states[i] = 1         
                            except:
                                pass
                        elif con_states[i] == 1:
                            try:
                                #peer_addr = sock_clients[i].getpeername()
                                con_states[i] = 2
                                new_con = Connection(sock_clients[i])
                                sockets.append(new_con)
                                log.info('send hello to [%s]' % (new_con.addr[0]))
                                new_con.send(peer.peer_hello())    # send HELLO
                            except:
                                pass
                        
                    if 2 in con_states:
                        rlist, wlist, elist = yield Select(sockets, [], sockets, 1)
                        if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
                            if not core.running: break
                        
                        timestamp = time.time()
                        for con in rlist:
                            con.idle_time = timestamp
                            if con.read() is False:
                                con.close()
                                sockets.remove(con)
                                #con_state = 0               # FIXME:
                            
            except exceptions.KeyboardInterrupt:
                log.info("keyboard Interrupt")
                break
            except:
                doTraceback = True
                if sys.exc_info()[0] is socket.error:
                    if sys.exc_info()[1][0] == ECONNRESET:
                        con.info("Connection reset")
                        doTraceback = False
                if doTraceback:
                    log.exception("Exception reading connection " + str(self.con))
                try:
                    con.close()
                except:
                    pass
                try:
                    sockets.remove(con)
                except:
                    pass
    
        log.debug("No longer listening for connections")


class Peer_Server_Task(Task):
    def __init__(self, port = 2555, address = '0.0.0.0'):
        Task.__init__(self)
        self.port = int(port)
        self.address = address
        self.started = False
    
        core.addListener(pox.core.GoingUpEvent, self._handle_GoingUpEvent)
        
    def _handle_GoingUpEvent(self, event):
        self.start()
        
    def start(self):
        if self.started:
            return
        self.started = True
        return super(Peer_Server_Task,self).start()
    
    def run(self):
        sockets = []
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.address, self.port))
        except socket.error as (errno, strerror):
            log.error("Error %i while binding socket: %s", errno, strerror)
            if errno == EADDRNOTAVAIL:
                log.error(" You may be specifying a local address which is "
                      "not assigned to any interface.")
            elif errno == EADDRINUSE:
                log.error(" You may have another controller running.")
                log.error(" Use openflow.of_01 --port=<port> to run POX on "
                      "another port.")
            return
        listener.listen(16)
        sockets.append(listener)
        log.debug("Peer Listening on %s:%s" % (self.address, self.port))
        
        
        con = None
        while core.running:
            try:
                while True:
                    con = None
                    #print '55555555555555'
                    rlist, wlist, elist = yield Select(sockets, [], sockets, 1)
                    
                    if len(rlist) == 0 and len(wlist) == 0 and len(elist) == 0:
                        if not core.running: break
                    for con in elist:
                        if con is listener:
                            raise RuntimeError("Error on listener socket")
                        else:
                            try:
                                con.close()
                            except:
                                pass
                            try:
                                sockets.remove(con)
                            except:
                                pass
        
                    timestamp = time.time()
                    for con in rlist:
                        if con is listener:
                            new_sock = listener.accept()[0]
                            new_sock.setblocking(0)
                            # Note that instantiating a Connection object fires a
                            # ConnectionUp event (after negotation has completed)
                            #print "new controller connected",new_sock.getpeername()
                            newcon = Connection(new_sock)        # generate a new instance of class 'Connection'
                            sockets.append(newcon)
                            
                        else:
                            con.idle_time = timestamp
                            if con.read() is False:    # do the read function of class 'Connection'
                                con.close()
                                sockets.remove(con)
                                
            except exceptions.KeyboardInterrupt:
                log.info("keyboard Interrupt")
                break
            except:
                doTraceback = True
                if sys.exc_info()[0] is socket.error:
                    if sys.exc_info()[1][0] == ECONNRESET:
                        con.info("Connection reset")
                        doTraceback = False
        
                if doTraceback:
                    log.exception("Exception reading connection " + str(con))
        
                if con is listener:
                    log.error("Exception on OpenFlow listener.  Aborting.")
                    break
                try:
                    con.close()
                except:
                    pass
                try:
                    sockets.remove(con)
                except:
                    pass
    
        log.debug("No longer listening for connections")


def _set_handlers ():
    handlers.extend([None] * (1 + sorted(handlerMap.keys(),reverse=True)[0]))
    for h in handlerMap:
        handlers[h] = handlerMap[h]
        #print handlerMap[h]
_set_handlers()

        
def launch (port = 2555, address = "0.0.0.0"):
    if core.hasComponent('peer_client') or core.hasComponent('peer_server'):
        return None

    peer_server = Peer_Server_Task(port = int(port), address = address)
    core.register("peer_server", peer_server)
    
    peers = '192.168.109.191,192.168.109.120'
    peers = peers.split(',')
    log.info('need to connect peers: %s' % (peers))
    peer_client = Peer_Client_Task(port = int(port), address = peers)
    core.register("peer_client", peer_client)
