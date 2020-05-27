'''
Created on 2015.12.23

@author: shengrulee
'''

import socket
import threading
import datetime

HOST = '127.0.0.1'
PORT = 6655
ADDR = (HOST, PORT)
BUFSIZE = 1024

INTER_CONTROLLER = '192.168.109.231'

# inter-domain rules 'ip': (dpid, output_port)
inter_domain_forwarding_rules = {'202.38.64.1': (0x0000001bcd0310ae, 1)}


class InterDomainConnection(object):

    def __init__(self, sock):
        self.sock = sock


class InterDomainClient(threading.Thread):

    def __init__(self, ip_addr, port):
        threading.Thread.__init__(self)
        self.peer_controller_addr = (ip_addr, port)

        inter_domain_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        inter_domain_client.connect(self.peer_controller_addr)
        while 1:
            data = inter_domain_client.recv(BUFSIZE)
            if data is None:
                break


class InterDomainServer(threading.Thread):

    def __init__(self, name=''):
        threading.Thread.__init__(self)
        self.name = name

    def establish_connection(self):
        inter_domain_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        inter_domain_server.bind(ADDR)
        inter_domain_server.listen(5)
        while 1:
            print 'waiting for other controller to connect...'
            conn, addr = inter_domain_server.accept()
            print 'catch a connection from %s' % addr

            inter_domain_server.send('hello')




            while 1:
                data = inter_domain_server.recv(BUFSIZE)
                if not data:
                    break

                print data

    def connect_to(self):
        inter_domain_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        inter_domain_client.connect((INTER_CONTROLLER, PORT))
        inter_domain_client.send('hello from client')



    def run(self):
        self.res = apply(self.establish_connection())
        
    def getResult(self):
        return self.res


if __name__ == '__main__':
    domain1 = InterDomainThread('domain1')
    domain1.run()


