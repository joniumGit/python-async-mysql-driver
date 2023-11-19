from typing import Callable, Awaitable, Tuple, TypeVar, Iterable

T = TypeVar('T')

WRITER = Callable[[bytes], Awaitable[None]]
READER = Callable[[int], Awaitable[bytes]]
WRITER_P = Callable[[int, bytes], Awaitable[None]]
READER_P = Callable[[], Awaitable[Tuple[bool, int, bytes]]]

MAX_PACKET = 16777215


def to_int(value: bytes) -> int:
    return int.from_bytes(
        value,
        byteorder='little',
        signed=False,
    )


def to_bytes(length: int, value: int) -> bytes:
    return int.to_bytes(
        value,
        length=length,
        byteorder='little',
        signed=False,
    )


def take(value: bytes, n: int, f: Callable[[bytes], T]) -> Tuple[T, bytes]:
    return f(value[:n]), value[n:]


def next_seq(seq: int) -> int:
    return (seq + 1) % 256


def split(data: bytes) -> Iterable[bytes]:
    view = memoryview(data)
    length = len(view)
    for i in range(0, length, MAX_PACKET):
        yield view[i:i + MAX_PACKET]
    if length % MAX_PACKET == 0:
        yield b''


async def read_message(reader: READER_P, expected_seq: int) -> Tuple[int, bytes]:
    output = bytearray()
    last = False
    while not last:
        last, seq, data = await reader()
        if seq != expected_seq:
            raise ValueError(
                'Unexpected sequence!'
                f'\n expected: {expected_seq}'
                f'\n got:      {seq}'
            )
        expected_seq = next_seq(seq)
        output.extend(data)
    return expected_seq, output


async def write_message(writer: WRITER_P, seq: int, data: bytes) -> int:
    for part in split(data):
        await writer(seq, part)
        seq = next_seq(seq)
    return seq
