from dataclasses import dataclass
from typing import Optional, Dict

from .constants import Response, ServerStatus, Capabilities, Commands
from .datatypes import Reader, Writer


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
class EOFPacket:
    warnings: Optional[int]
    status_flags: Optional[ServerStatus]


@dataclass
class OKPacket:
    affected_rows: int
    last_insert_id: int
    status_flags: ServerStatus
    warnings: Optional[int]
    info: str
    session_state_info: Optional[str]


@dataclass
class ERRPacket:
    code: int
    state_marker: Optional[str]
    state: Optional[str]
    error: str


@dataclass
class InfilePacket:
    filename: str


class MySQLPacketFactory:
    _capabilities: Capabilities

    def __init__(self, capabilities: Capabilities):
        self._capabilities = capabilities

    def parse_ok(self, data: bytes):
        capabilities = self._capabilities
        reader = Reader(data)
        args = [
            reader.int_lenenc(),
            reader.int_lenenc(),
        ]
        if Capabilities.PROTOCOL_41 in capabilities:
            args.append(ServerStatus(reader.int(2)))
            args.append(reader.int(2))
        elif Capabilities.TRANSACTIONS:
            args.append(ServerStatus(reader.int(2)))
            args.append(None)
        else:
            args.append(None)
            args.append(None)
        if Capabilities.SESSION_TRACK in capabilities:
            args.append(reader.int_lenenc())
            if args[2] and ServerStatus.SESSION_STATE_CHANGED in args[2]:
                args.append(reader.str_lenenc())
            else:
                args.append(None)
        else:
            args.append(reader.str_eof())
            args.append(None)
        return OKPacket(*args)

    def parse_err(self, data: bytes):
        capabilities = self._capabilities
        reader = Reader(data)
        if Capabilities.PROTOCOL_41 in capabilities:
            return ERRPacket(
                reader.int(2),
                reader.str(1),
                reader.str(2),
                reader.str_eof(),
            )
        else:
            return ERRPacket(
                reader.int(2),
                None,
                None,
                reader.str_eof(),
            )

    def identify(self, data: bytes):
        capabilities = self._capabilities
        header = data[0]
        if header == Response.EOF and len(data) < 9:
            if Capabilities.DEPRECATE_EOF in capabilities:
                return Response.OK, data[1:]
            else:
                return Response.EOF, data[1:]
        elif header == Response.OK and len(data) > 7:
            return Response.OK, data[1:]
        return None, data

    def parse_response(self, data: bytes):
        capabilities = self._capabilities
        type, data = self.identify(data)
        if type == Response.EOF:
            if Capabilities.PROTOCOL_41 in capabilities:
                reader = Reader(data)
                return EOFPacket(
                    reader.int(2),
                    ServerStatus(reader.int(2)),
                )
            else:
                return EOFPacket(
                    None,
                    None,
                )
        elif type == Response.OK:
            return self.parse_ok(data)
        elif type == Response.ERR:
            return self.parse_err(data)

    def create_query(self, stmt: str):
        writer = Writer()
        writer.int(1, Commands.QUERY)
        if Capabilities.QUERY_ATTRIBUTES in self._capabilities:
            raise ValueError('Implement Attributes')
        writer.str_eof(stmt)
        return bytes(writer)

    @staticmethod
    def parse_handshake(data: bytes):
        reader = Reader(data)
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
            server_version,
            thread_id,
            auth_plugin_data_1,
            filler,
            capabilities,
            charset,
            status,
            auth_plugin_data_len,
            reserved,
            auth_plugin_data_2,
            auth_plugin_name,
        )

    @staticmethod
    def write_handshake_response(p: HandshakeResponse41):
        writer = Writer()
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
