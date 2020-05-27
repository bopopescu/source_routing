'''
Created on Dec 23, 2014

@author: root
'''
import struct

PEER_VERSION = 0x01
MAX_XID = 0x7fFFffFF

def XIDGenerator(start = 1, stop = MAX_XID):
    i = start
    while True:
        yield i
        i += 1
        if i > stop:
            i = start
            
generate_xid = XIDGenerator(1, MAX_XID).next

# ----------------------------------------------------------------------
# Packing / Unpacking
# ----------------------------------------------------------------------

class UnderrunError (RuntimeError):
    """
    Raised when one tries to unpack more data than is available
    """
    pass

def _read (data, offset, length):
    if (len(data)-offset) < length:
        raise UnderrunError("wanted %s bytes but only have %s"
                        % (length, len(data)-offset))
    return (offset+length, data[offset:offset+length])

def _unpack (fmt, data, offset):
    size = struct.calcsize(fmt)
    if (len(data)-offset) < size:
        raise UnderrunError()
    return (offset+size, struct.unpack_from(fmt, data, offset))

def _skip (data, offset, num):
    offset += num
    if offset > len(data):
        raise UnderrunError()
    return offset

def _unpad (data, offset, num):
    (offset, o) = _read(data, offset, num)
    assert len(o.replace("\x00", "")) == 0
    return offset

def _readzs (data, offset, length):
    (offset, d) = _read(data, offset, length)
    d = d.split("\x00", 1)
    assert True if (len(d) == 1) else (len(d[1].replace("\x00", "")) == 0)
    return (offset, d[0])

# ----------------------------------------------------------------------
# Class decorators
# ----------------------------------------------------------------------

_message_type_to_class = {}
_message_class_to_types = {}
peer_type_rev_map = {}
peer_type_map = {}

def peer_message (peer_type, type_val):
    peer_type_rev_map[peer_type] = type_val 
    peer_type_map[type_val] = peer_type
    def f (c):
        c.header_type = type_val
        _message_type_to_class[type_val] = c
        _message_class_to_types.setdefault(c, set()).add(type_val)
        return c
    return f

# ----------------------------------------------------------------------
# Structure definitions
# ----------------------------------------------------------------------

#1. Peer Header
class peer_header (object):
    _MIN_LENGTH = 8
    
    def __init__ (self, **kw):
        self.version = PEER_VERSION
        self._xid = None
        if 'header_type' in kw: 
            self.header_type = kw.pop('header_type')

    @property
    def xid (self):
        if self._xid is None:
            self._xid = generate_xid()
        return self._xid

    @xid.setter
    def xid (self, val):
        self._xid = val

    def pack (self):
        packed = b""
        packed += struct.pack("!BBHL", self.version, self.header_type,
            len(self), self.xid)
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        return offset,length

    def _unpack_header (self, raw, offset):
        offset,(self.version, self.header_type, length, self.xid) = \
            _unpack("!BBHL", raw, offset)
        return offset,length
    
    @classmethod
    def unpack_new (cls, raw, offset=0):
        o = cls()
        r, length = o.unpack(raw, offset)
        assert (r - offset) == length, o
        return (r, o)

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if self.version != other.version: return False
        if self.header_type != other.header_type: return False
        if len(self) != len(other): return False
        if self.xid != other.xid: return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'version: ' + str(self.version) + '\n'
        outstr += prefix + 'type:    ' + str(self.header_type)
        outstr += " (" + peer_type_map.get(self.header_type, "Unknown") + ")\n"
        outstr += prefix + 'length:  ' + str(len(self)) + '\n'
        outstr += prefix + 'xid:     ' + str(self.xid) + '\n'
        return outstr

    def __str__ (self):
        return self.__class__.__name__ + "\n  " + self.show('  ').strip()


#2. Peer Messages
@peer_message("PEER_HELLO", 0)
class peer_hello(peer_header):
    _MIN_LENGTH = peer_header._MIN_LENGTH
    
    def __init__ (self, **kw):
        peer_header.__init__(self)

    def pack (self):
        packed = b""
        packed += peer_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset,length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not peer_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += peer_header.show(self, prefix + '  ')
        return outstr
    
@peer_message("PEER_ERROR", 1)  # FIXME:
class peer_error(peer_header):
    _MIN_LENGTH = peer_header._MIN_LENGTH
    
    def __init__ (self, **kw):
        peer_header.__init__(self)

    def pack (self):
        packed = b""
        packed += peer_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset,length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not peer_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += peer_header.show(self, prefix + '  ')
        return outstr
    
@peer_message("PEER_ECHO_REQUEST", 2)
class peer_echo_request(peer_header):
    _MIN_LENGTH = peer_header._MIN_LENGTH
    
    def __init__ (self, **kw):
        peer_header.__init__(self)

    def pack (self):
        packed = b""
        packed += peer_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset,length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not peer_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += peer_header.show(self, prefix + '  ')
        return outstr
    
@peer_message("PEER_ECHO_REPLY", 3)
class peer_echo_reply(peer_header):
    _MIN_LENGTH = peer_header._MIN_LENGTH
    
    def __init__ (self, **kw):
        peer_header.__init__(self)

    def pack (self):
        packed = b""
        packed += peer_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset,length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not peer_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += peer_header.show(self, prefix + '  ')
        return outstr
    
@peer_message("PEER_FEATURES_REPORT", 4)
class peer_features_report(peer_header):
    _MIN_LENGTH = peer_header._MIN_LENGTH
    
    def __init__ (self, **kw):
        peer_header.__init__(self)

    def pack (self):
        packed = b""
        packed += peer_header.pack(self)
        return packed

    def unpack (self, raw, offset=0):
        offset,length = self._unpack_header(raw, offset)
        assert length == len(self)
        return offset,length

    @staticmethod
    def __len__ ():
        return 8

    def __eq__ (self, other):
        if type(self) != type(other): return False
        if not peer_header.__eq__(self, other): return False
        return True

    def show (self, prefix=''):
        outstr = ''
        outstr += prefix + 'header: \n'
        outstr += peer_header.show(self, prefix + '  ')
        return outstr
    

    
def _init ():
    def formatMap (name, m):
        o = name + " = {\n"
        vk = sorted([(v,k) for k,v in m.iteritems()])
        maxlen = 2 + len(reduce(lambda a,b: a if len(a)>len(b) else b,
                                (v for k,v in vk)))
        fstr = "  %-" + str(maxlen) + "s : %s,\n"
        for v,k in vk:
            o += fstr % ("'" + k + "'",v)
        o += "}"
        return o
    maps = []
    for k,v in globals().iteritems():
        if (k.startswith("peer_") and k.endswith("_rev_map") and type(v) == dict):
            maps.append((k[:-8],v))
    for name,m in maps:
        # Try to generate forward maps
        forward = dict(((v,k) for k,v in m.iteritems()))
        if len(forward) == len(m):
            if name + "_map" not in globals():
                globals()[name + "_map"] = forward
        else:
            print(name + "_rev_map is not a map")
    
        # Try to generate lists
        v = m.values()
        v.sort()
        if v[-1] != len(v)-1:
            # Allow ones where the last value is a special value (e.g., VENDOR)
            del v[-1]
        if len(v) > 0 and v[0] == 0 and v[-1] == len(v)-1:
            globals()[name] = v
    
        # Generate gobals
        for k,v in m.iteritems():
            globals()[k] = v

_init()


#print _message_type_to_class
#print _message_class_to_types
#print peer_type_rev_map
#print peer_type_map
