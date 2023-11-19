from .common import (
    write_message,
    read_message,
    READER,
    WRITER,
    READER_P,
    WRITER_P,
    take,
    to_int,
    to_bytes,
    MAX_PACKET,
)


def create_packet_reader(read: READER) -> READER_P:
    async def read_packet():
        length, data = take(await read(4), 3, to_int)
        seq = to_int(data)
        return length < MAX_PACKET, seq, await read(length)

    return read_packet


def create_packet_writer(drain: WRITER) -> WRITER_P:
    async def write_packet(seq: int, body: bytes):
        out = bytearray(to_bytes(3, len(body)))
        out.extend(to_bytes(1, seq))
        out.extend(body)
        await drain(out)

    return write_packet


class ProtoPlain:
    seq: int

    def __init__(
            self,
            writer: WRITER,
            reader: READER,
    ):
        self.seq = 0
        self.writer = create_packet_writer(writer)
        self.reader = create_packet_reader(reader)

    def reset(self) -> None:
        self.seq = 0

    async def send(self, data: bytes) -> None:
        self.seq = await write_message(
            self.writer,
            self.seq,
            data,
        )

    async def recv(self) -> bytes:
        self.seq, output = await read_message(
            self.reader,
            self.seq,
        )
        return output
