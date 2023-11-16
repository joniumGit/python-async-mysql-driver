from asyncio import StreamReader, StreamWriter, wait_for
from dataclasses import dataclass
from typing import Union

from protocol.constants import SEQ_MODULO, MAX_PACKET
from protocol.datatypes import Writer, Reader


def next_seq(seq):
    return (seq + 1) % SEQ_MODULO


async def read(stream: StreamReader, n: int, timeout: float):
    return await wait_for(stream.readexactly(n), timeout=timeout)


async def drain(stream: StreamWriter, timeout: float):
    return await wait_for(stream.drain(), timeout=timeout)


async def read_packet(stream: StreamReader, timeout: float):
    reader = Reader(await read(stream, 4, timeout))
    length = reader.int(3)
    seq = reader.int(1)
    body = await read(stream, length, timeout)
    return RawPacket(length, seq, body)


async def parse_packet_from_stream(
        stream: StreamReader,
        seq: Union[int, None],
        timeout: float,
):
    output = bytearray()
    last = False
    while not last:
        p = await read_packet(stream, timeout)
        if seq is not None and p.seq != seq:
            raise ValueError(
                'Unexpected sequence!'
                f'\n expected: {seq}'
                f'\n got:      {p.seq}'
            )
        else:
            seq = next_seq(p.seq)
        if p.length > 0:
            output.extend(p.body)
        last = p.length < MAX_PACKET
    return seq, output


@dataclass(slots=True)
class RawPacket:
    length: int
    seq: int
    body: bytes


def to_wire(packet: RawPacket):
    writer = Writer()
    writer.int(3, packet.length)
    writer.int(1, packet.seq)
    writer.bytes(packet.length, packet.body)
    return bytes(writer)


def to_packet(seq: int, body: bytes):
    return RawPacket(len(body), seq, body)


class ProtoPlain:
    seq: int
    timeout: float
    writer: StreamWriter
    reader: StreamReader

    def __init__(
            self,
            writer: StreamWriter,
            reader: StreamReader,
            timeout: float = 2,
    ):
        self.seq = 0
        self.timeout = timeout
        self.writer = writer
        self.reader = reader

    def reset(self):
        self.seq = 0

    def _create_packet(self, data: bytes):
        seq = self.seq
        p = to_packet(seq, data)
        self.seq = next_seq(seq)
        return p

    def _send_small(self, data: bytes):
        self.writer.write(to_wire(self._create_packet(data)))

    def _split_packets(self, data: bytes):
        view = memoryview(data)
        length = len(view)
        for i in range(0, length, MAX_PACKET):
            yield self._create_packet(bytes(view[i:i + MAX_PACKET]))
        if length % MAX_PACKET == 0:
            yield self._create_packet(b'')

    def _send_big(self, data: bytes):
        for p in self._split_packets(data):
            self.writer.write(to_wire(p))

    async def send(self, data: bytes):
        if len(data) >= MAX_PACKET:
            self._send_big(data)
        else:
            self._send_small(data)
        await drain(self.writer, self.timeout)

    async def send_stream(self, stream: StreamReader):
        data = await read(stream, MAX_PACKET, self.timeout)
        while data:
            await self.send(data)
            data = await read(stream, MAX_PACKET, self.timeout)

    async def _recv_plain(self):
        self.seq, output = await parse_packet_from_stream(
            self.reader,
            seq=self.seq,
            timeout=self.timeout,
        )
        return output

    async def recv(self):
        return await self._recv_plain()
