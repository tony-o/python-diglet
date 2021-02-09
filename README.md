# diglet

a pure python3 dns query tool

## usage

```python3
import diglet

resp = diglet.Mkreq('google.com', qtype=diglet.QType.A)
# use resp to make that $$$
# more info: https://www.ietf.org/rfc/rfc1035.txt

print(resp)
#{'header': {'id': 26519,
#             'qr': 'response',
#             'opcode': <OpCode.QUERY: 0>,
#             'aa': False,
#             'tc': False,
#             'rd': True,
#             'ra': True,
#             'z': 0,
#             'rcode': <ReturnCode.NO_ERROR: 0>,
#             'qdcount': 1,
#             'ancount': 1,
#             'nscount': 0,
#             'arcount': 0
#            },
# 'questions': [{'qname': 'google.com.',
#                'qtype': <QType.A: 1>,
#                'qclass': <Class.IN: 1>
#               }
#              ],
# 'answers': [{'aname': 'google.com.',
#              'atype': <Type.A: 1>,
#              'aclass': <Class.IN: 1>,
#              'attl': 236,
#              'ardlen': 4,
#              'ardata':
#              '142.250.72.206'
#             }
#            ],
# 'authority': {}
#}
```
