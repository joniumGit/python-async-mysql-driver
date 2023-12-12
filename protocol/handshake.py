from dataclasses import dataclass
from typing import Optional, Dict

from .authentication import native_password
from .charsets import CHARSETS, PYTHON_CHARSETS
from .constants import ServerStatus, Capabilities
from .datatypes import Reader, Writer
from .packets import read_ack
from .wire import MAX_PACKET, ProtoPlain, READER, WRITER
from .wire.common import next_seq


@dataclass
class HandshakeV10:
    server_version: str
    thread_id: int
    auth_data_1: bytes
    filler: int
    capabilities: Capabilities
    charset: int
    status: ServerStatus
    auth_data_length: int
    reserved: bytes
    auth_data_2: Optional[bytes]
    auth_plugin_name: Optional[str]

    @property
    def auth_data(self):
        return self.auth_data_1 + self.auth_data_2


@dataclass
class HandshakeResponse41:
    client_flag: Capabilities
    max_packet: int
    charset: int
    filler: bytes
    username: str
    auth_response: bytes
    database: Optional[str] = None
    client_plugin_name: Optional[str] = None
    attrs_length: Optional[int] = None
    attrs: Optional[Dict[str, str]] = None
    compression_level: Optional[int] = None


@dataclass
class SSLRequest:
    client_flag: Capabilities
    max_packet: int
    charset: int
    filler: bytes


def parse_handshake(data: bytes):
    reader = Reader(data, 'ascii')
    protocol_version = reader.int(1)
    if protocol_version != 10:
        raise ValueError(
            'Unknown protocol'
            'expected: 10'
            f'got:    {protocol_version}'
        )
    server_version = reader.str_null()
    thread_id = reader.int(4)
    auth_plugin_data_1 = reader.bytes(8)
    filler = reader.int(1)
    cap_lower = reader.int(2)
    charset = reader.int(1)
    status = ServerStatus(reader.int(2))
    cap_upper = reader.int(2)
    capabilities = Capabilities((cap_upper << 16) | cap_lower)
    if Capabilities.PLUGIN_AUTH in capabilities:
        auth_plugin_data_len = reader.int(1)
    else:
        auth_plugin_data_len = 0
    reserved = reader.bytes(6)
    if Capabilities.MYSQL in capabilities:
        reserved += reader.bytes(4)
    else:
        capabilities |= Capabilities(reader.int(4) << 32)
    if Capabilities.PLUGIN_AUTH in capabilities:
        auth_plugin_data_2 = reader.bytes(max((13, auth_plugin_data_len - 8)))
        auth_plugin_name = reader.str_null()
    else:
        auth_plugin_data_2 = None
        auth_plugin_name = None
    if reader.remaining():
        raise ValueError('Remaining handshake data')
    return HandshakeV10(
        server_version=server_version,
        thread_id=thread_id,
        auth_data_1=auth_plugin_data_1,
        filler=filler,
        capabilities=capabilities,
        charset=charset,
        status=status,
        auth_data_length=auth_plugin_data_len,
        reserved=reserved,
        auth_data_2=auth_plugin_data_2,
        auth_plugin_name=auth_plugin_name,
    )


def encode_handshake_response(p: HandshakeResponse41):
    writer = Writer('ascii')
    writer.int(4, p.client_flag)
    writer.int(4, p.max_packet)
    writer.int(1, p.charset)
    writer.bytes(23, p.filler)
    writer.str_null(p.username)
    if Capabilities.PLUGIN_AUTH_LENENC_CLIENT_DATA in p.client_flag:
        writer.bytes_lenenc(p.auth_response)
    else:
        size = len(p.auth_response)
        writer.int(1, size)
        writer.bytes(size, p.auth_response)
    if p.database is not None:
        writer.str_null(p.database)
    if p.client_plugin_name is not None:
        writer.bytes_null(p.client_plugin_name.encode('utf-8'))
    if p.attrs_length is not None:
        writer.int_lenenc(p.attrs_length)
    if p.attrs:
        for k, v in p.attrs.items():
            writer.str_lenenc(k)
            writer.str_lenenc(v)
    if p.compression_level:
        writer.int(1, p.compression_level)
    return bytes(writer)


def encode_ssl_request(p: SSLRequest):
    writer = Writer('ascii')
    writer.int(4, p.client_flag)
    writer.int(4, p.max_packet)
    writer.int(1, p.charset)
    writer.bytes(23, p.filler)
    return bytes(writer)


def check_charset(charset: str):
    try:
        return CHARSETS[charset], PYTHON_CHARSETS[charset]
    except KeyError:
        raise LookupError('Unsupported charset %s' % charset)


class ProtoHandshake(ProtoPlain):
    initialized = False

    def reset(self) -> None:
        self.initialized = False

    async def recv(self) -> bytes:
        if not self.initialized:
            self.initialized = True
            last, seq, data = await self.reader()
            self.seq = next_seq(seq)
            if not last:
                data += await super(ProtoHandshake, self).recv()
            return data
        else:
            return await super(ProtoHandshake, self).recv()


class NativePasswordHandshake:
    server: HandshakeV10
    client: HandshakeResponse41

    _wire: ProtoHandshake
    _capabilities: Capabilities

    def __init__(
            self,
            writer: WRITER,
            reader: READER,
            capabilities: Capabilities,
    ):
        self._wire = ProtoHandshake(writer, reader)
        self._capabilities = capabilities

    async def connect(
            self,
            username: str,
            password: str,
            charset: str,
            database: str = None,
            enable_ssl=None
    ):
        charset_code, charset_python = check_charset(charset)

        self.server = parse_handshake(await self._wire.recv())

        capabilities = self._capabilities & self.server.capabilities

        if database is not None:
            if Capabilities.CONNECT_WITH_DB not in self.server.capabilities:
                raise ValueError('CONNECT_WITH_DB not supported')
            else:
                capabilities |= Capabilities.CONNECT_WITH_DB

        if enable_ssl:
            if Capabilities.SSL not in self.server.capabilities:
                raise ValueError('SSL not supported')
            capabilities |= Capabilities.SSL
            await self._wire.send(encode_ssl_request(SSLRequest(
                client_flag=capabilities,
                max_packet=MAX_PACKET,
                charset=charset_code,
                filler=b'\x00' * 23,
            )))
            await enable_ssl()

        self.client = HandshakeResponse41(
            client_flag=capabilities,
            max_packet=MAX_PACKET,
            charset=charset_code,
            filler=b'\x00' * 23,
            username=username,
            auth_response=native_password(password, self.server.auth_data),
            client_plugin_name='mysql_native_password',
            database=database,
        )

        await self._wire.send(encode_handshake_response(self.client))

        ok_packet = await read_ack(
            self._wire,
            charset_python,
            capabilities,
        )

        self._wire.reset()

        return ok_packet, charset_python, capabilities
