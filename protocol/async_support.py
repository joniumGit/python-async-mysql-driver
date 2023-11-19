from asyncio import StreamReader, StreamWriter, wait_for

from .wire import READER, WRITER


def create_stream_reader(stream: StreamReader, timeout: float) -> READER:
    async def read(n: int):
        return await wait_for(stream.readexactly(n), timeout=timeout)

    return read


def create_stream_writer(stream: StreamWriter, timeout: float) -> WRITER:
    async def drain(data: bytes):
        stream.write(data)
        return await wait_for(stream.drain(), timeout=timeout)

    return drain
