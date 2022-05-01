import asyncio as aio
import dataclasses
from textwrap import dedent
from zlib import compress, decompress
import typing as t
from hashlib import sha1

from enum import IntFlag

NEWLINE = '\n'
ENID: t.Literal['little', 'big'] = 'little'
MAX_PACKET_PART = int(2 ** 24 - 1)
B_MAX_PACKET_PART = MAX_PACKET_PART.to_bytes(length=3, byteorder=ENID)
B_ZERO = (0).to_bytes(length=1, byteorder=ENID)
SEQ_MAX = 15

CHARSETS: t.Dict[str, int] = {
    'utf8mb4': 255
}


class Capabilities(IntFlag):
    CLIENT_LONG_PASSWORD = 0x00000001
    CLIENT_FOUND_ROWS = 0x00000002
    CLIENT_LONG_FLAG = 0x00000004
    CLIENT_CONNECT_WITH_DB = 0x00000008
    CLIENT_NO_SCHEMA = 0x00000010
    CLIENT_COMPRESS = 0x00000020
    CLIENT_ODBC = 0x00000040
    CLIENT_LOCAL_FILES = 0x00000080
    CLIENT_IGNORE_SPACE = 0x00000100
    CLIENT_PROTOCOL_41 = 0x00000200
    CLIENT_INTERACTIVE = 0x00000400
    CLIENT_SSL = 0x00000800
    CLIENT_IGNORE_SIGPIPE = 0x00001000
    CLIENT_TRANSACTIONS = 0x00002000
    CLIENT_RESERVED = 0x00004000
    CLIENT_SECURE_CONNECTION = 0x00008000
    CLIENT_MULTI_STATEMENTS = 0x00010000
    CLIENT_MULTI_RESULTS = 0x00020000
    CLIENT_PS_MULTI_RESULTS = 0x00040000
    CLIENT_PLUGIN_AUTH = 0x00080000
    CLIENT_CONNECT_ATTRS = 0x00100000
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS = 0x00400000
    CLIENT_SESSION_TRACK = 0x00800000
    CLIENT_DEPRECATE_EOF = 0x01000000
    # MARIADB
    CLIENT_CAPABILITY_EXTENSION = 1 << 29
    CLIENT_ZSTD_COMPRESSION_ALGORITHM = 1 << 26
    MARIADB_CLIENT_PROGRESS = 1 << 32
    MARIADB_CLIENT_STMT_BULK_OPERATIONS = 1 << 34
    MARIADB_CLIENT_EXTENDED_TYPE_INFO = 1 << 35
    MARIADB_CLIENT_CACHE_METADATA = 1 << 36


class Status(IntFlag):
    SERVER_STATUS_IN_TRANS = 0x0001
    SERVER_STATUS_AUTOCOMMIT = 0x0002
    SERVER_MORE_RESULTS_EXISTS = 0x0008
    SERVER_STATUS_NO_GOOD_INDEX_USED = 0x0010
    SERVER_STATUS_NO_INDEX_USED = 0x0020
    SERVER_STATUS_CURSOR_EXISTS = 0x0040
    SERVER_STATUS_LAST_ROW_SENT = 0x0080
    SERVER_STATUS_DB_DROPPED = 0x0100
    SERVER_STATUS_NO_BACKSLASH_ESCAPES = 0x0200
    SERVER_STATUS_METADATA_CHANGED = 0x0400
    SERVER_QUERY_WAS_SLOW = 0x0800
    SERVER_PS_OUT_PARAMS = 0x1000
    SERVER_STATUS_IN_TRANS_READONLY = 0x2000
    SERVER_SESSION_STATE_CHANGED = 0x4000


def pretty_repr(i: IntFlag):
    r = repr(i).lstrip('<').rstrip('>')
    if '.' in r:
        r = r.split('.', 1)[1]
    if '|' in r:
        r = r.split('|', 1)[1]
    if ':' in r:
        r = r.split(':', 1)[0]
    return r


def sequence():
    out = 0
    while True:
        yield out
        out = out + 1 if out < 15 else 0


def compressed_sequence():
    out = 0
    while True:
        yield out
        out = out + 1 if out < 15 else 0


def packet(seq: int, body: bytes):
    return body.__len__().to_bytes(
        length=3,
        byteorder=ENID,
        signed=False
    ) + seq.to_bytes(
        length=1,
        byteorder=ENID,
        signed=False
    ) + body


def compressed_packet(seq: int, body: bytes):
    if body.__len__() > 50:
        payload = compress(body)
        return payload.__len__().to_bytes(
            length=3,
            byteorder=ENID,
            signed=False
        ) + seq.to_bytes(
            length=1,
            byteorder=ENID,
            signed=False
        ) + body.__len__().to_bytes(
            length=3,
            byteorder=ENID,
            signed=False
        ) + payload
    else:
        return body.__len__().to_bytes(
            length=3,
            byteorder=ENID,
            signed=False
        ) + seq.to_bytes(
            length=1,
            byteorder=ENID,
            signed=False
        ) + (0).to_bytes(
            length=3,
            byteorder=ENID,
            signed=False
        ) + body


@dataclasses.dataclass(frozen=False)
class ServerHandshake:
    protocol_version: int
    server_version: str
    connection_id: int
    # Late init
    capabilities: Capabilities = Capabilities(0)
    auth_data: bytes = bytes()
    # Optional
    charset: t.Optional[int] = None
    status: Status = Status(0)
    auth_plugin: t.Optional[str] = None


@dataclasses.dataclass(frozen=False)
class ClientHandshake41:
    username: bytes

    capabilities: Capabilities = Capabilities.CLIENT_PROTOCOL_41
    max_packet_size: int = MAX_PACKET_PART
    charset: int = 255  # utf8mb4


def client_handshake_41(
        auth_data: bytes,
        username: str,
        password: str,
        database: t.Optional[str] = None,
        charset: str = 'utf8mb4',
        capabilities: Capabilities = Capabilities(0),

):
    password = password.encode('utf-8')
    password = bytes(
        a ^ b
        for a, b in
        zip(
            sha1(password).digest(),
            sha1(auth_data + sha1(sha1(password).digest()).digest()).digest()
        )
    )
    return (
            (
                    capabilities
                    | Capabilities.CLIENT_SECURE_CONNECTION
                    | Capabilities.CLIENT_PROTOCOL_41
                    | Capabilities.CLIENT_PLUGIN_AUTH
                    | Capabilities.CLIENT_DEPRECATE_EOF
                    | (Capabilities.CLIENT_CONNECT_WITH_DB if database is not None else 0)
            ).to_bytes(length=4, byteorder=ENID, signed=False)
            + MAX_PACKET_PART.to_bytes(length=4, byteorder=ENID, signed=False)
            + CHARSETS[charset].to_bytes(length=1, byteorder=ENID, signed=False)
            + b'\x00' * 23
            + username.encode('utf-8') + b'\x00'
            + (20).to_bytes(length=1, byteorder=ENID, signed=False)
            + password
            + (
                database.encode('utf-8') + b'\x00'
                if database is not None else
                bytes()
            )
            + b'mysql_native_password\x00'
    )


def interpret_server_handshake(data: bytes) -> ServerHandshake:
    capabilities = Capabilities(0)

    proto_version = data[0]
    server_version, _, data = data[1:].partition(b'\x00')
    connection_id = int.from_bytes(
        data[0:4],
        byteorder=ENID,
        signed=False
    )
    auth_plugin_data_1 = data[4:12]
    capability_bot = int.from_bytes(
        data[13:15],
        byteorder=ENID,
        signed=False
    )
    capabilities |= capability_bot

    # TODO: Debug
    print(dedent(
        f"""
            ------BASIC------
            Protocol version: {proto_version}
            Server version:   {server_version.decode('ascii')}
            Connection id:    {connection_id}
            Auth data 1:      {auth_plugin_data_1.hex()}
            Capability (bot): |{pretty_repr(Capabilities(capability_bot))}
            """
    ).strip().replace('|', '\n' + ' ' * 18))

    shake = ServerHandshake(
        protocol_version=proto_version,
        server_version=server_version.decode('ascii'),
        connection_id=connection_id
    )

    data = data[15:]
    if len(data) != 0:
        charset = data[0]
        status = Status(int.from_bytes(
            data[1:3],
            byteorder=ENID,
            signed=False
        ))
        capability_top = int.from_bytes(
            data[3:5],
            byteorder=ENID,
            signed=False
        ) << 16
        capabilities |= capability_top
        data = data[5:]

        # TODO: Debug
        print(dedent(
            f"""
            -------OPT-------
            Charset:          {charset}
            Status flags:     |{pretty_repr(status)}
            Capability (top): |{pretty_repr(Capabilities(capability_top))}
            """
        ).strip().replace('|', '\n' + ' ' * 18))

        if capabilities & Capabilities.CLIENT_PLUGIN_AUTH:
            len_auth_data = data[0]
        else:
            len_auth_data = 0
        data = data[1:]

        # Reserved (MYSQL 10, MARIADB 6)
        is_mariadb = b'maria' in server_version
        data = data[6:]
        if is_mariadb:
            capabilities_maria = int.from_bytes(
                data[:4],
                byteorder=ENID,
                signed=False
            ) << 32
            capabilities |= capabilities_maria
            print(dedent(
                f"""
                ------MARIA------
                Capability (Mdb): |{repr(Capabilities(capabilities_maria)).split('|', 1)[1].split(':', 1)[0]}
                """
            ).strip().replace('|', '\n' + ' ' * 18))
        data = data[4:]

        if capabilities & Capabilities.CLIENT_SECURE_CONNECTION:
            if is_mariadb:
                # One reserved byte at the end
                if len_auth_data > 0:
                    auth_plugin_data_2 = data[:len_auth_data - 9]
                    data = data[max((len_auth_data - 9, 13)):]
                else:
                    auth_plugin_data_2 = data[:12]
                    data = data[13:]
            else:
                if len_auth_data > 0:
                    auth_plugin_data_2 = data[:len_auth_data - 8]
                    data = data[max((len_auth_data - 8, 13)):]
                else:
                    auth_plugin_data_2 = data[:13]
                    data = data[13:]
        else:
            auth_plugin_data_2 = bytes()

        if capabilities & Capabilities.CLIENT_PLUGIN_AUTH:
            auth_plugin_name, _, e = data.partition(b'\x00')
        else:
            auth_plugin_name = None

        # TODO: Debug
        print(dedent(
            f"""
            -------OPT-------
            Auth data length: {len_auth_data}
            Auth data 2:      {auth_plugin_data_2.hex()}
            Auth plugin name: {(auth_plugin_name or '').decode('ascii')}
            -----------------
            """
        ).strip())

        shake.auth_data = auth_plugin_data_1 + auth_plugin_data_2
        shake.auth_plugin = auth_plugin_name.decode('ascii') if auth_plugin_name is not None else None
        shake.charset = charset
        shake.status = status
    else:
        shake.auth_data = auth_plugin_data_1

    shake.capabilities = capabilities
    return shake


def read_lenenc(data: bytes) -> t.Tuple[int, bytes]:
    size = data[0]
    if size == 0xfc:  # 2 Byte
        value = data[2:4]
        data = data[4:]
    elif size == 0xfd:  # 3 Byte
        value = data[2:5]
        data = data[5:]
    elif size == 0xfe:  # 8 Byte
        value = data[2:5]
        data = data[5:]
    else:
        value = size
        data = data[1:]
    return value, data


def interpret_response(data: bytes):
    _type = data[0]
    if _type == 0x00:
        affected_rows, data = read_lenenc(data)
        last_insert_id, data = read_lenenc(data)
        status = Status(int.from_bytes(data[0:2], byteorder=ENID, signed=False))
        warnings = int.from_bytes(data[2:4], byteorder=ENID, signed=False)
        info = data[4:]
        # TODO: Debug
        print(f'Type: OK')
        print(f'Affected rows: {affected_rows:d}')
        print(f'Status:        {pretty_repr(status)}')
        print(f'Warning:       {warnings}')
        print(f'Info:          {info}')
    elif _type == 0xfe:
        # TODO: Debug
        print(f'Type: EOF')
    elif _type == 0xff:
        code = int.from_bytes(data[1:3], byteorder=ENID, signed=True)
        marker = chr(data[4])
        state = data[4:9].decode('ascii')
        error = data[9:]
        # TODO: Debug
        print(f'Type: ERR')
        print(f'Code:   {code:d}')
        print(f'Marker: {marker}')
        print(f'State:  {state}')
        print(f'Error:  {error}')
    else:
        # TODO: Debug
        print(f'Type: 0x{_type:0>2x}')


async def write(body: bytes, next_seq: int, writer: aio.streams.StreamWriter) -> int:
    payload_length = len(body)
    if payload_length >= MAX_PACKET_PART:
        i = 0
        for i in range(0, payload_length, MAX_PACKET_PART):
            writer.write(packet(next_seq, body[i: i + MAX_PACKET_PART]))
            next_seq = (next_seq + 1) % 16
        writer.write(packet(next_seq, body[i + MAX_PACKET_PART:]))
        next_seq = (next_seq + 1) % 16
    else:
        writer.write(packet(next_seq, body))
        next_seq = (next_seq + 1) % 16
    await writer.drain()
    return next_seq


async def read(next_seq: int, reader: aio.streams.StreamReader, compressed: bool = False) -> t.Tuple[bytes, int]:
    data: bytes = bytes()
    if compressed:
        len_read = MAX_PACKET_PART
        while len_read == MAX_PACKET_PART:
            header = await reader.readexactly(7)
            len_read, seq, len_data = int.from_bytes(
                header[0:3],
                byteorder=ENID,
                signed=False
            ), header[3], int.from_bytes(
                header[4:7],
                byteorder=ENID,
                signed=False
            )

            assert seq == next_seq
            next_seq = (seq + 1) % 16

            if len_read != 0:
                if len_data == 0:
                    data += await reader.readexactly(len_read)
                else:
                    data += decompress(await reader.readexactly(len_read))
    else:
        len_read = MAX_PACKET_PART
        while len_read == MAX_PACKET_PART:
            header = await reader.readexactly(4)
            len_read, seq = int.from_bytes(header[0:3], byteorder=ENID, signed=False), header[3]

            assert seq == next_seq
            next_seq = (seq + 1) % 16

            if len_read != 0:
                data += await reader.readexactly(len_read)

    return data, next_seq


async def create_connection(
        host: str,
        port: int,
        username: str,
        password: str,
        database: t.Optional[str] = None,
        charset: str = 'utf8mb4',
):
    reader, writer = await aio.open_connection(host=host, port=port)
    response, next_seq = await read(0, reader)
    print(f'Read Server Handshake')
    shake = interpret_server_handshake(response)
    print()

    response = client_handshake_41(shake.auth_data, username, password, database, charset)
    next_seq = await write(response, next_seq, writer)
    print(f'Sent Client Handshake')
    response, next_seq = await read(next_seq, reader)
    interpret_response(response)
    print()

    next_seq = await write(b'\x03SELECT 1,2', 0, writer)
    print(f'Sent SELECT')
    response, next_seq = await read(next_seq, reader)
    num_cols, data = read_lenenc(response)
    print(f'Column Count: {num_cols}')

    for i in range(0, num_cols):
        response, next_seq = await read(next_seq, reader)
        print(response)

    print()

    print(f'Sleep')
    await aio.sleep(1)
    print()

    next_seq = await write(b'\x01', 0, writer)
    print(f'Sent Quit')
    writer.close()


async def test_main():
    await create_connection(
        '127.0.0.1',
        3306,
        'root',
        'local'
    )


if __name__ == '__main__':
    aio.run(test_main())
