from BaseHTTPServer import *
from pox.core import core
import os.path
from pox.web.webcore import *
import cgi
from pox.lib.util import dpidToStr
import json

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

class EXtemplate():
    def __init__ (self):
        httpd = core.WebServer
        httpd.set_handler("/", requestHandler, httpd, True)
        print "url has been built"


class requestHandler(SplitRequestHandler):

    def do_GET (self):
        self.wfile.write(f)

    def do_POST (self):
        data={}
        form = cgi.FieldStorage(fp=self.rfile,
                                headers=self.headers,
                                environ={'REQUEST_METHOD':'POST',
                                         'CONTENT_TYPE':self.headers['Content-Type'],
                                         })
        #print 'form fp:',form.fp.read()
        print 'form type:', type(form)
        print "***************************"
        method_name=form.getvalue('method_name')
        print 'method_name:',method_name
        f=json.dumps(protocol)
        self.send_response(200)
        self.send_header('Content-type','application/json')
        self.send_header('Content-Length',f)
        self.end_headers()
        self.wfile.write(f)

        #json.dump(data,self.wfile)


def launch ():
    core.registerNew(EXtemplate)
