"""
Author: shengrulee
Date: 2015.12.28

This file is to realize the communication between two POF controllers.
"""

from pox.lib.revent.revent import EventMixin
from pox.lib.revent.revent import Event
import pox.openflow.libpof_02 as of
from pox.core import core
from pox.lib.addresses import IPAddr


import json
import socket
import threading
import errno

import BaseHTTPServer
import urllib2
import urlparse
from SocketServer import ThreadingMixIn

from pox.web.webcore import SplitRequestHandler, SplitThreadedServer

log = core.getLogger()

HOST = '192.168.109.120'
PORT = 6655
ADDR = (HOST, PORT)
BUFSIZE = 1024

neighbor_controllers = ['192.168.109.231', '192.168.1.109']

url = "http://192.168.109.230:8000"

protocol = {
    'type': 'protocol',
    'name': 'Ethernet',
    'fieldList':[{'name':'DMAC',
                  'offset': 0,
                  'length': 48},
                 {'name':'SMAC',
                  'offset': 48,
                  'length': 48},
                 {'name':'type',
                  'offset': 96,
                  'length': 16}]
}

inter_domain_table = {
    'type': 'forwardingTable',
    'table': [{'dstIP':'192.168.1.10/24',
               'output': 2},
              {'dstIP':'192.168.109.150/32',
               'output': 3},
              {'dstIP':'10.0.0.2/16',
               'output': 4}]
}

path_setup_req = {
    'type': 'path_setup_request',
    'matchList':[{'name':'SrcIP',
                  'offset': 200,
                  'length':32,
                  'value':'192.168.1.10'},
                 {'name':'DstIP',
                   'offset': 232,
                'length':32,
                'value': '10.0.0.1'}]
                 }

KEEP_RUNNING = True


def ip2hex(ip_addr):

    ip_list = ip_addr.split('.')
    #print ip_list
    ip_hex = ''
    for each in ip_list:
        each_hex = hex(int(each))
        each_hex = each_hex[2:]
        if len(each_hex) == 1:
            each_hex = '0' + each_hex
        #print each_hex
        ip_hex = ip_hex + each_hex
        #print ip_hex
    return ip_hex


class InterDomainRequestHandler(SplitRequestHandler):

    def do_POST(self):
        print 'handle post'
        parsed_path = urlparse.urlparse(self.path)
        length = self.headers.getheader('content-length')
        nbytes = int(length)
        data_json = self.rfile.read(nbytes)

        data = json.loads(data_json)
        print data

        message_parts = ['received message']
        message = '\r\n'.join(message_parts)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(message)

        core.InterDomainConnection.raiseEvent(InterDomainRequest, data, parsed_path)



class ThreadingHttpServer(ThreadingMixIn, BaseHTTPServer.HTTPServer ):
    pass


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


def inter_domain_client(url, data):
    print 'in function client'
    while 1:

        req = urllib2.Request(url, json.dumps(data), {'Content-Type':'application/json'})
        try:
            response = urllib2.urlopen(req)
            print response
            break
        except urllib2.URLError, e:
            pass


def send_msg_to_server(url,data):
    req = urllib2.Request(url, json.dumps(data), {'Content-Type':'application/json'})
    try:
        response = urllib2.urlopen(req)
        print response.read()
    except urllib2.URLError, e:
        print 'urlerror'
        pass


def create_inter_domain_server():
    http_server = core.WebServer
    http_server.set_handler('/', InterDomainRequestHandler, http_server, True)
    log.info('IDM server for inter-domain is runnning ... ')
    # server = SplitThreadedServer(('127.0.0.1',8000), RequestHandler)
    # ip, port = server.server_address
    # print "ssssss"
    #
    # while keep_running():
    #     server.handle_request()
    #
    # #server_thread = threading.Thread(target=server.serve_forever())
    # print "sqqqqq"
    #server_thread.setDaemon(True)
    #server_thread.start()
    #log.info("Server loop running in thread:" % server_thread.getName())

class PathSetupReq(object):
    def __init__(self, req):
        self.match_list = []
        self.matchx_list = []
        if req['type'] == 'path_setup_request':
            field_id = 0
            for each_field in req['matchList']:
                match_field = of.ofp_match20(field_name = each_field['name'],
                                             field_id = field_id,
                                             offset = each_field['offset'],
                                             length = each_field['length'])
                self.match_list.append(match_field)

                matchx_field = of.ofp_matchx(field_name = match_field.field_name,
                                             field_id = match_field.field_id,
                                             offset = match_field.offset,
                                             length = match_field.length,
                                             value = ip2hex(each_field['value']))  #  value is hex string
                print matchx_field.value
                self.matchx_list.append(matchx_field)
                field_id += 1

        else:
            log.error('path setup req : type error')


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
        log.info("set up IDM server...")
        # server_threading = MyThread(inter_domain_server(), 'server_threading')
        # server_threading.setDaemon(True)
        # server_threading.start()
        create_inter_domain_server()

        # create and start the client thread
        # log.info("set up interdomain client...")
        # client_thread = MyThread(inter_domain_client(url, protocol), 'client_thread')
        # client_thread.setDaemon(True)
        # client_thread.start()
        # #inter_domain_client(url, protocol)

        send_msg_to_server(url, protocol)


    def _handle_InterDomainRequest(self, event):
        print "got the inter domain request"
        print event.data

        dpid = 2215152430

        path_setup_req = event.data
        req = PathSetupReq(path_setup_req)

        core.PofManager.add_flow_table(dpid, 'FirstEntryTable', of.OF_MM_TABLE, 32, req.match_list)  #0
        action_1 = core.PofManager.new_action_output(0, 0, 0, 0, 0x2)  # output
        temp_ins = core.PofManager.new_ins_apply_actions([action_1])
        table_id = 0
        core.PofManager.add_flow_entry(dpid, table_id, req.matchx_list, [temp_ins])


def launch():
    core.registerNew(InterDomainConnection)
