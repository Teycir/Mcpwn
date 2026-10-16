"""OOB detection regression tests (port collision must not crash the scan)"""
import socket

from tests.oob_detection import OOBTest


class _StubPentester:
    def __init__(self, config):
        self.config = config
        self.captured = []

    def health_check(self):
        return True

    def send(self, method, params=None, **kwargs):
        self.captured.append((method, params))
        return {}, 0.0


def _occupied_udp_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    return sock, sock.getsockname()[1]


def test_oob_listener_bind_failure_is_not_fatal():
    """A busy listener port must skip OOB, not abort the scan"""
    sock, port = _occupied_udp_port()
    try:
        oob = OOBTest(_StubPentester({'oob_dns_port': port}))
        tool = {'name': 't', 'inputSchema':
                {'properties': {'cmd': {}}}}
        findings = oob.run(tool)
        assert findings == []
        assert oob.dns_server is None
    finally:
        sock.close()


def test_oob_defaults_to_dns_port_53():
    """Payloads dial the default resolver port, so the listener must match"""
    assert OOBTest(_StubPentester({})).dns_port == 53
