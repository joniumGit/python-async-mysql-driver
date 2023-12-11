from zlib import decompress, compress

from .common import (
    READER,
    WRITER,
    WRITER_P,
    READER_P,
    take,
    to_int,
    to_bytes,
    MAX_PACKET,
    write_message,
    read_message,
    next_seq,
)
from .plain import ProtoPlain


def create_compressed_packet_reader(read: READER) -> READER_P:
    async def read_packet():
        length, data = take(await read(7), 3, to_int)
        seq, data = take(data, 1, to_int)
        uncompressed_length = to_int(data)
        data = await read(length)
        if uncompressed_length > 0:
            data = decompress(data)
            if len(data) != uncompressed_length:
                raise ValueError('Compression length mismatch')
        return length < MAX_PACKET, seq, data

    return read_packet


def create_compressed_packet_writer(
        drain: WRITER,
        threshold: int,
        level: int,
) -> WRITER_P:
    async def write_packet(seq: int, body: bytes):
        length = len(body)
        if length > threshold:
            uncompressed_length = len(body)
            body = compress(body, level=level)
            length = len(body)
        else:
            uncompressed_length = 0
        out = bytearray(to_bytes(3, length))
        out += to_bytes(1, seq)
        out += to_bytes(3, uncompressed_length)
        out += body
        await drain(out)

    return write_packet


class ProtoCompressed(ProtoPlain):
    seq_compressed: int

    def __init__(
            self,
            writer: WRITER,
            reader: READER,
            threshold: int = 50,
            level: int = 1,
    ):
        super(ProtoCompressed, self).__init__(
            self.write,
            self.read,
        )
        self.seq_compressed = 0
        self.read_buffer = bytearray()
        self.write_buffer = bytearray()
        self.writer_compressed = create_compressed_packet_writer(
            writer,
            threshold,
            level,
        )
        self.reader_compressed = create_compressed_packet_reader(
            reader,
        )

    def reset(self):
        super(ProtoCompressed, self).reset()
        self.seq_compressed = 0

    async def send(self, data: bytes):
        await super(ProtoCompressed, self).send(data)
        await self.send_compressed(self.write_buffer)
        self.write_buffer.clear()

    async def send_compressed(self, data: bytes):
        self.seq_compressed = await write_message(
            self.writer_compressed,
            self.seq_compressed,
            data,
        )

    async def send_one_max_packet_compressed(self):
        await self.writer_compressed(
            self.seq_compressed,
            self.write_buffer[:MAX_PACKET],
        )
        self.seq_compressed = next_seq(self.seq_compressed)
        self.write_buffer[:MAX_PACKET] = b''

    async def recv_compressed(self):
        self.seq_compressed, output = await read_message(
            self.reader_compressed,
            self.seq_compressed,
        )
        self.read_buffer += output

    async def write(self, data: bytes):
        self.write_buffer += data
        if len(self.write_buffer) >= MAX_PACKET:
            await self.send_one_max_packet_compressed()

    async def read(self, n: int):
        buffer = self.read_buffer
        if len(buffer) < n:
            await self.recv_compressed()
        if len(buffer) < n:
            raise EOFError('Not enough data')
        data = buffer[:n]
        buffer[:n] = b''
        return data
