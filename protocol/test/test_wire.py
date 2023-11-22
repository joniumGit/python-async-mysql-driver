from unittest import IsolatedAsyncioTestCase

from ..wire.common import split, MAX_PACKET


class TestCommon(IsolatedAsyncioTestCase):

    def test_split_exact_produces_empty_packet(self):
        payload = b'a' * MAX_PACKET
        p1, p2 = [p for p in split(payload)]
        assert p1 == payload
        assert p2 == b''

    def test_split_non_exact_produces_partial_packet(self):
        payload = b'a' * MAX_PACKET + b'bcd'
        p1, p2 = [p for p in split(payload)]
        assert p1 == b'a' * MAX_PACKET
        assert p2 == b'bcd'
