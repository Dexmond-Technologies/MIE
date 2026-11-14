'''X9: writable+executable sections count once per file.
(Stand-in PE parser: PASS UNDER MOCK.)'''
from fakepe import FakeSection, analyzer


def test_wx_counted_once():
    a = analyzer(sections=[FakeSection('UPX0', 0.0, 'RWX'), FakeSection('UPX1', 6.0, 'RWX'),
                           FakeSection('.data', 3.0, 'RW')])
    wx = [w for w in a._check_anomalies() if 'writable and executable' in w.lower()]
    assert len(wx) == 1 and 'UPX0' in wx[0] and 'UPX1' in wx[0]


def test_no_wx_no_warning():
    a = analyzer(sections=[FakeSection('.text', 6.0, 'RX'), FakeSection('.data', 3.0, 'RW')])
    assert not any('executable section' in w for w in a._check_anomalies())
