from unittest import IsolatedAsyncioTestCase

from ..wire.common import split, MAX_PACKET, write_message
from ..wire.compressed import ProtoCompressed


def create_writer():
    output = []

    async def writer(data: bytes):
        output.append(data)

    return output, writer


def create_sequenced_writer():
    output = []

    async def sequenced_writer(seq: int, data: bytes):
        output.append((seq, data))

    return output, sequenced_writer


def create_reader():
    buffer = bytearray()

    async def reader(length: int):
        data = buffer[:length]
        buffer[:length] = b''
        return data

    return buffer, reader


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

    async def test_write_empty_bytes_writes_once(self):
        payload = b''
        seq = 0
        output, writer = create_sequenced_writer()
        await write_message(writer, seq, payload)
        assert output == [(0, payload)], 'Expected a single write'

    async def test_compressed_early_send(self):
        output, writer = create_writer()
        buffer, reader = create_reader()
        proto = ProtoCompressed(writer, reader)

        await proto.write(b' ' * (MAX_PACKET - 1))
        assert len(output) == 0

        await proto.write(b' ')
        assert len(output) == 1, 'No early write detected'
