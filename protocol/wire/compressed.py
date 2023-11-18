from asyncio import StreamReader, StreamWriter
from collections import deque
from dataclasses import dataclass
from typing import Iterable
from zlib import decompress, compress

from .plain import ProtoPlain, RawPacket, next_seq, to_wire, read
from ..constants import MAX_PACKET
from ..datatypes import Reader, Writer


async def read_compressed(stream: StreamReader, timeout: float):
    reader = Reader(await read(stream, 7, timeout))
    length = reader.int(3)
    seq = reader.int(1)
    uncompressed_length = reader.int(3)
    return RawCompressedPacket(
        length,
        seq,
        uncompressed_length,
        await read(stream, length, timeout),
    )


async def parse_compressed_from_stream(
        stream: StreamReader,
        seq: int,
        timeout: float,
):
    buffer = bytearray()
    last = False
    while not last:
        p = await read_compressed(stream, timeout)
        if p.seq != seq:
            raise ValueError(
                'Unexpected sequence!'
                f'\n expected: {seq}'
                f'\n got:      {p.seq}'
            )
        else:
            seq = next_seq(p.seq)
        if p.length > 0:
            buffer.extend(
                decompress(p.compressed)
                if p.uncompressed_length > 0 else
                p.compressed
            )
        last = p.length < MAX_PACKET
    return seq, buffer


def read_one(packet_data_buffer: bytes):
    if len(packet_data_buffer) >= 4:
        reader = Reader(packet_data_buffer)
        length = reader.int(3)
        seq = reader.int(1)
        if len(reader) >= length:
            body = reader.bytes(length)
            return RawPacket(length, seq, body), reader.remaining()
    return None, packet_data_buffer


def parse_packets_from_buffer_to_queue(
        buffer: bytes,
        seq: int,
        dest: deque,
):
    remaining = buffer
    p, remaining = read_one(remaining)
    while p is not None:
        if p.seq != seq:
            raise ValueError(
                'Unexpected sequence!'
                f'\n expected: {seq}'
                f'\n got:      {p.seq}'
            )
        else:
            seq = next_seq(p.seq)
        dest.append(p.body)
        p, remaining = read_one(remaining)
    return seq, remaining


@dataclass(slots=True)
class RawCompressedPacket:
    length: int
    seq: int
    uncompressed_length: int
    compressed: bytes


def compressed(seq: int, body: bytes):
    data = compress(body)
    return RawCompressedPacket(
        len(data),
        seq,
        len(body),
        data,
    )


def compressed_plain(seq: int, body: bytes):
    return RawCompressedPacket(
        len(body),
        seq,
        0,
        body,
    )


def to_wire_compressed(packet: RawCompressedPacket):
    writer = Writer()
    writer.int(3, packet.length)
    writer.int(1, packet.seq)
    writer.int(3, packet.uncompressed_length)
    writer.bytes(packet.length, packet.compressed)
    return bytes(writer)


class ProtoCompressed(ProtoPlain):
    seq: int
    seq_compressed: int
    threshold: int

    writer: StreamWriter
    reader: StreamReader

    def __init__(
            self,
            writer: StreamWriter,
            reader: StreamReader,
            threshold: int,
    ):
        super(ProtoCompressed, self).__init__(writer, reader)
        self.seq_compressed = 0
        self.threshold = threshold
        self.queue = deque()
        self.buffer = bytes()

    def reset(self):
        super(ProtoCompressed, self).reset()
        self.seq_compressed = 0

    def _send_small(self, data: bytes):
        seq = self.seq_compressed
        payload = to_wire(self._create_packet(data))
        if len(data) > self.threshold:
            p = compressed(seq, payload)
        else:
            p = compressed_plain(seq, payload)
        self.writer.write(to_wire_compressed(p))
        self.seq_compressed = next_seq(seq)

    def _compress_packets(self, packets: Iterable[RawPacket]):
        seq = self.seq_compressed
        buffer = bytearray()
        for packet in map(to_wire, packets):
            if len(buffer) + len(packet) < MAX_PACKET:
                buffer.extend(packet)
            else:
                yield compressed(seq, buffer)
                seq = next_seq(seq)
                buffer = bytearray(packet)
        if buffer:
            yield compressed(seq, buffer)
            seq = next_seq(seq)
            if len(buffer) == MAX_PACKET:
                yield RawCompressedPacket(0, seq, 0, b'')
                seq = next_seq(seq)
        self.seq_compressed = seq

    def _split_packets_compressed(
            self,
            data: bytes,
    ):
        yield from self._compress_packets(
            self._split_packets(
                data,
            ),
        )

    def _send_big(self, data: bytes):
        for p in self._split_packets_compressed(data):
            self.writer.write(to_wire_compressed(p))

    async def _recv_compressed(self):
        self.seq_compressed, buffer = await parse_compressed_from_stream(
            self.reader,
            seq=self.seq_compressed,
            timeout=self.timeout,
        )
        self.seq, self.buffer = parse_packets_from_buffer_to_queue(
            self.buffer + buffer,
            seq=self.seq,
            dest=self.queue,
        )

    async def recv(self):
        if not self.queue:
            await self._recv_compressed()
        return self.queue.popleft()
