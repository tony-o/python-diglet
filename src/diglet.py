from random import randrange
from struct import pack, unpack_from
from enum import Enum
import socket
import time
import sys

class Class(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4

class OpCode(Enum):
    QUERY = 0
    IQUERY = 1
    STATUS = 2
    RESERVED = 3
    NOTIFY = 4
    UPDATE = 5

class ReturnCode(Enum):
    NO_ERROR = 0
    FORMAT_ERROR=1
    SERVER_FAILURE=2
    NAME_ERROR=3
    NOT_IMPLEMENTED=4
    REFUSED=5
    YX_DOMAIN=6
    YX_RR_SET=7
    NX_RR_SET=8
    NOT_AUTH=9
    NOT_ZONE=10

class Type(Enum):
    A=1
    AAAA=28
    NS=2
    MD=3
    MF=4
    CNAME=5
    SOA=6
    MB=7
    MG=8
    MR=9
    NULL=10
    WKS=11
    PTR=12
    HINFO=13
    MINFO=14
    MX=15
    TXT=16

class QType(Enum):
    A=1
    AAAA=28
    NS=2
    MD=3
    MF=4
    CNAME=5
    SOA=6
    MB=7
    MG=8
    MR=9
    NULL=10
    WKS=11
    PTR=12
    HINFO=13
    MINFO=14
    MX=15
    TXT=16
    AXFR=252
    MAILB=253
    MAILA=254
    ASTERIK=255

def Mkreq(name, qtype=QType.A, nameserver='8.8.8.8'):
    rid   = randrange(65535)
    req   = mkhead(recurse=1,
                   name=name,
                   qtype=qtype
                  )
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((nameserver, 53))
    s.sendall(bytearray(req))
    read = b''
    while True:
        chunk,addr = s.recvfrom(512)
        if not chunk:
            break
        read += chunk
        break
    s.close()
    result = rdmsg(read)
    return result

def rdmsg(data):
    d = {'header': {},
         'questions': [],
         'answers': [],
         'authority': {},
         }

    # HEADER
    d['header']['id'] = bigEuntuple(unpack_from('!BB', data, 0))
    d['header']['qr'] = 'response' if unpack_from('!B', data, 2)[0] & 0b10000000 else 'query'
    d['header']['opcode'] = OpCode((unpack_from('!B', data, 2)[0] & 0b01111000) >> 3)
    d['header']['aa'] = True if unpack_from('!B', data, 2)[0] & 0b00000100 else False
    d['header']['tc'] = True if unpack_from('!B', data, 2)[0] & 0b00000010 else False
    d['header']['rd'] = True if unpack_from('!B', data, 2)[0] & 0b00000001 else False

    d['header']['ra'] = True if unpack_from('!B', data, 3)[0] & 0b10000000 else False
    d['header']['z'] = unpack_from('!B', data, 3)[0] & 0b01110000 # should always be zero
    d['header']['rcode'] = ReturnCode(unpack_from('!B', data, 3)[0] & 0b00001111)
    d['header']['qdcount'] = bigEuntuple(unpack_from('!BB', data, 4))
    d['header']['ancount'] = bigEuntuple(unpack_from('!BB', data, 6))
    d['header']['nscount'] = bigEuntuple(unpack_from('!BB', data, 8))
    d['header']['arcount'] = bigEuntuple(unpack_from('!BB', data, 10))
    # these should be a different enum
    if d['header']['rcode'] != ReturnCode.NO_ERROR \
    or d['header']['tc']:
        return d

    # QUESTIONS
    idx = 0
    ridx = 12
    while len(d['questions']) < d['header']['qdcount']:
        d['questions'].append({'qname': '',
                               'qtype': '',
                               'qclass': '',
                              })
        d['questions'][idx]['qname'], ridx = readNS(data, ridx)
        ridx += 1
        d['questions'][idx]['qtype'] = QType(bigEuntuple(unpack_from('!BB', data, ridx)))
        d['questions'][idx]['qclass'] = Class(bigEuntuple(unpack_from('!BB', data, ridx + 2)))
        ridx += 3
    ridx += 1
    if data[ridx:]:
        while len(d['answers']) < d['header']['ancount'] + d['header']['nscount']:
            d['answers'].append({'aname': '',
                                 'atype': '',
                                 'aclass': '',
                                 'attl': -1,
                                 'ardlen': -1,
                                 'ardata': -1,
                                })
            d['answers'][-1]['aname'], ridx = readNS(data, ridx)
            d['answers'][-1]['atype'] = Type(bigEuntuple(unpack_from('!BB', data, ridx)))
            d['answers'][-1]['aclass'] = Class(bigEuntuple(unpack_from('!BB', data, ridx+2)))
            d['answers'][-1]['attl'] = bigEuntuple(unpack_from('!BBBB', data, ridx+4))
            d['answers'][-1]['ardlen'] = bigEuntuple(unpack_from('!BB', data, ridx+8))
            d['answers'][-1]['ardata'] = unpack_from('<'+str(d['answers'][-1]['ardlen'])+'s', data, ridx+10)[0]
            ridx += 10 + d['answers'][-1]['ardlen']
            if d['answers'][-1]['atype'] == Type.A: #A record
                d['answers'][-1]['ardata'] = decodeIP(d['answers'][-1]['ardata']) 
            if d['answers'][-1]['atype'] == Type.AAAA:
                d['answers'][-1]['ardata'] = decodeIP6(d['answers'][-1]['ardata'])
            if d['answers'][-1]['atype'] == Type.NS: #NS
                d['answers'][-1]['ardata'], _ = readNS(data, ridx - d['answers'][-1]['ardlen'])
            if d['answers'][-1]['atype'] == Type.MD: #MD OBSOLETE
                pass
            if d['answers'][-1]['atype'] == Type.MF: #MF OBSOLETE
                pass
            if d['answers'][-1]['atype'] == Type.CNAME: #CNAME
                d['answers'][-1]['ardata'], _ = readNS(d['answers'][-1]['ardata'], 0)
            if d['answers'][-1]['atype'] == Type.SOA: #SOA
                xidx = ridx - d['answers'][-1]['ardlen']
                mname, i = readNS(data, xidx)
                rname, i = readNS(data, i)
                serial = bigEuntuple(unpack_from('!BBBB', data, i))
                refresh = bigEuntuple(unpack_from('!BBBB', data, i + 4))
                retry = bigEuntuple(unpack_from('!BBBB', data, i + 8))
                expire = bigEuntuple(unpack_from('!BBBB', data, i + 12))
                d['answers'][-1]['ardata'] = {
                    'mname': mname,
                    'rname': rname,
                    'serial': serial,
                    'refresh': refresh,
                    'retry': retry,
                    'expire': expire,
                }
            if d['answers'][-1]['atype'] == Type.MB: #MB
                d['answers'][-1]['ardata'], _ = readNS(data, ridx - d['answers'][-1]['ardlen'])
            if d['answers'][-1]['atype'] == Type.MG: #MG
                d['answers'][-1]['ardata'], _ = readNS(data, ridx - d['answers'][-1]['ardlen'])
            if d['answers'][-1]['atype'] == Type.MR: #MR
                d['answers'][-1]['ardata'], _ = readNS(data, ridx - d['answers'][-1]['ardlen'])
            if d['answers'][-1]['atype'] == Type.NULL: #NULL
                pass
            if d['answers'][-1]['atype'] == Type.WKS: #WKS
                ip = decodeIP(d['answers'][-1]['ardata'][0:4])
                proto = d['answers'][-1]['ardata'][5]
                bitmap = d['answers'][-1]['ardata'][6:]
                d['answers'][-1]['ardata'] = {
                    'ip': ip,
                    'protocol': proto,
                    'bitmap': bitmap,
                }
            if d['answers'][-1]['atype'] == Type.PTR: #PTR
                d['answers'][-1]['ardata'], _ = readNS(data, ridx - d['answers'][-1]['ardlen'])
            if d['answers'][-1]['atype'] == Type.HINFO: #HINFO USED BY CLOUDFLARE
                pass
            if d['answers'][-1]['atype'] == Type.MINFO: #MINFO NOT USED .. 
                xidc = ridx - d['answers'][-1]['ardlen']
                rmailbx, xidc = readNS(data, xidc)
                emailbx, xidc = readNS(data, xidc)
                d['answers'][-1]['ardata'] = {
                    'rmailbx': rmailbx,
                    'emailbx': emailbx,
                }
            if d['answers'][-1]['atype'] == Type.MX: #MX
                pref = bigEuntuple(unpack_from('!BB', d['answers'][-1]['ardata'], 0))
                (nms, _) = readNS(data, ridx - d['answers'][-1]['ardlen'] + 2)
                d['answers'][-1]['ardata'] = {
                    'preference': pref,
                    'exchange': nms,
                }
            if d['answers'][-1]['atype'] == Type.TXT: #TXT
                d['answers'][-1]['ardata'] = d['answers'][-1]['ardata'][1:].decode()

    if len(data) > ridx:
        raise Exception('Unread data: {}'.format( data[ridx:] ))
    return d

def dump(d):
    print(':'.join('{:02x}'.format(x) for x in d))

def readNS(data, offset, cacheAt=-1):
    ns = ''
    os = offset
    while data[os] != 0:
        rd = data[os]
        if rd & 0b1100_0000 != 0:
            (x, i) = readNS(data, data[os + 1])
            return (ns + x, os + 2)
        ns += unpack_from('<{}s'.format(rd), data, os + 1)[0].decode()
        os += 1 + rd
        ns += '.'
    return (ns, os)

def decodeIP(x):
    if len(x) != 4:
        raise Exception('Expect length four for IP')
    return str(x[0]) + '.' + str(x[1]) + '.' + str(x[2]) + '.' + str(x[3])

def decodeIP6(x):
    if len(x) != 16:
        raise Exception('Expect length 16 for IPv6')
    ip = ''.join('{:04x}'.format((x[i*2] << 8) + x[(i * 2)+1]) for i in range(8))
    # shorten ipv6
    ls = list(range(0, len(ip)))
    ls[len(ip) - 1] = 0
    x = (0, 0)
    for i in range(len(ip)-2, -1, -1):
        ls[i] = ls[i+1] + 1 if ip[i] == '0' else 0
        if ls[i] > x[0]:
            x = (ls[i], i)
    ips = '{}::{}'.format(
        ':'.join([ ''.join(ip[i:i+4]) for i in range(0, x[1], 4) ]),
        ':'.join([ ''.join(ip[i:i+4]) for i in range(x[1]+x[0], len(ip), 4) ]),
    )
    return ips

def bigEuntuple(x):
    j = len(x) - 2
    i = x[j+1]
    while j >= 0:
        i += x[j] << 8
        j -= 1
    return i

def mkns(domain):
    bstr = b''
    domain = domain.encode().split(b'.')
    bstr = b''.join(bytes([len(x)]) + x for x in domain) + b'\0'
    return bstr

def mkhead(recurse, name, qtype=Type.A, qclass=Class.IN):
    return pack('!HBBHHHH',
                randrange(65000),
                (1 if recurse else 0),
                0,
                1, #questions,
                0,
                0,
                0, # END OF HEADER
               ) \
         + mkns(name) \
         + pack('BBBB', (qtype.value >> 8) & 255, qtype.value & 255, (qclass.value >> 8) & 255, qclass.value & 255) 

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {} <domain> [<record type>+]', file=sys.stderr)
        sys.exit(255)
    name = sys.argv[1]
    types = [QType[x] for x in sys.argv[2:]] if len(sys.argv) >= 3 else [QType.A]
    for qt in types:
        print('>>= {}'.format(qt.name))
        res = Mkreq(name, qtype=qt)
        if res['header']['rcode'] != ReturnCode.NO_ERROR:
            print('; error: {}'.format(res['header']['rcode'].name), file=sys.stderr)
            next
        for ans in res.get('answers', []):
            if ans['atype'] == Type.SOA:
                print('{}\t{}\t{}\t{}\t{} {} {} {} {} {}'.format(
                    ans['aname'],
                    ans['attl'],
                    ans['atype'].name,
                    ans['aclass'].name,
                    ans['ardata']['mname'],
                    ans['ardata']['rname'],
                    ans['ardata']['serial'],
                    ans['ardata']['refresh'],
                    ans['ardata']['retry'],
                    ans['ardata']['expire'],
                ))
            else:
                print('{}\t{}\t{}\t{}\t{}'.format(ans['aname'], ans['attl'], ans['atype'].name, ans['aclass'].name, ans['ardata']))
