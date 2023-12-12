from asyncio import StreamReader, StreamWriter, wait_for, get_running_loop
from ssl import create_default_context, Purpose, VerifyMode

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


def create_ssl_enabler(
        writer: StreamWriter,
        reader: StreamReader,
        timeout: float,
        verify: bool = True,
):
    async def enable_ssl():
        ctx = create_default_context(Purpose.SERVER_AUTH)
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = VerifyMode.CERT_NONE
        ssl_transport = await get_running_loop().start_tls(
            writer.transport,
            writer.transport.get_protocol(),
            ctx,
            server_side=False,
            ssl_handshake_timeout=timeout,
        )
        writer._transport = ssl_transport
        reader._transport = ssl_transport

    return enable_ssl
