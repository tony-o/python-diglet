import pytest
import diglet

def test_live():
    resp = diglet.Mkreq('google.com', qtype=diglet.QType.A)
    assert(len(resp['answers']) > 0)
    resp = diglet.Mkreq('google.com', qtype=diglet.QType.MX)
    assert(len(resp['answers']) > 0)
