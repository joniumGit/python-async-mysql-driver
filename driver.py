import asyncio as aio
import typing as t
from enum import IntFlag
from hashlib import sha1
from zlib import compress, decompress

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


def split_flags_str(i: IntFlag):
    r = repr(i).lstrip('<').rstrip('>')
    if '.' in r:
        r = r.split('.', 1)[1]
    if '|' in r:
        r = r.split('|', 1)[1]
    if ':' in r:
        r = r.split(':', 1)[0]
    return r.split('|')


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


def calc_next_seq(current: int) -> int:
    return (current + 1) % 256


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


def interpret_server_handshake(data: bytes) -> bytes:
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

    print('------BASIC------')
    print('Protocol version:', proto_version)
    print('Server version:  ', server_version.decode())
    print('Connection id:   ', connection_id)
    print('Auth data 1:     ', auth_plugin_data_1.hex())
    print('Capabilities:    ', )
    for flag in split_flags_str(Capabilities(capability_bot)):
        print(' -', flag)

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

        print('-------OPT-------')
        print('Charset:         ', charset)
        print('Status flags:    ', )
        for flag in split_flags_str(status):
            print(' -', flag)
        print('Capabilities:    ', )
        for flag in split_flags_str(Capabilities(capability_top)):
            print(' -', flag)

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
            print('------MARIA------')
            for flag in split_flags_str(Capabilities(capabilities_maria)):
                print(' -', flag)
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

        print('-------OPT-------')
        print('Auth data length:', len_auth_data)
        print('Auth data 2:     ', auth_plugin_data_2.hex())
        print('Auth plugin name:', (auth_plugin_name or b'').decode('ascii'))

        return auth_plugin_data_1 + auth_plugin_data_2
    else:
        return auth_plugin_data_1


def read_lenenc(data: bytes) -> t.Tuple[bytes, bytes]:
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
        value = bytes([size])
        data = data[1:]
    return value, data


def read_lenenc_str(data: bytes) -> t.Tuple[str, bytes]:
    size, data = read_lenenc_int(data)
    return data[:size].decode(), data[size:]


def read_lenenc_int(data: bytes) -> t.Tuple[int, bytes]:
    value, data = read_lenenc(data)
    return int.from_bytes(value, byteorder=ENID), data


def interpret_response(data: bytes):
    _type = data[0]
    if _type == 0x00:
        affected_rows, data = read_lenenc_int(data)
        last_insert_id, data = read_lenenc_int(data)
        status = Status(int.from_bytes(data[0:2], byteorder=ENID, signed=False))
        warnings = int.from_bytes(data[2:4], byteorder=ENID, signed=False)
        info = data[4:-1]
        print('Type: OK')
        print('Affected rows: ', affected_rows)
        print('Last Insert id:', last_insert_id)
        print('Status:        ', )
        for flag in split_flags_str(status):
            print(' -', flag)
        print('Warning:       ', warnings)
        print('Info:          ', info.decode())
        return 'ok'
    elif _type == 0xfe:
        print('Type: EOF')
        return 'eof'
    elif _type == 0xff:
        code = int.from_bytes(data[1:3], byteorder=ENID, signed=True)
        marker = chr(data[4])
        state = data[4:9].decode('ascii')
        error = data[9:]
        print('Type: ERR')
        print('Code:   ', code)
        print('Marker: ', marker)
        print('State:  ', state)
        print('Error:  ', error)
        return 'err'


async def write(body: bytes, next_seq: int, writer: aio.streams.StreamWriter) -> int:
    payload_length = len(body)
    if payload_length >= MAX_PACKET_PART:
        i = 0
        for i in range(0, payload_length, MAX_PACKET_PART):
            writer.write(packet(next_seq, body[i: i + MAX_PACKET_PART]))
            next_seq = calc_next_seq(next_seq)
        writer.write(packet(next_seq, body[i + MAX_PACKET_PART:]))
        next_seq = calc_next_seq(next_seq)
    else:
        writer.write(packet(next_seq, body))
        next_seq = calc_next_seq(next_seq)
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

            assert seq == next_seq, f'Got unexpected SEQ {seq} expected {next_seq}'
            next_seq = calc_next_seq(seq)

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

            assert seq == next_seq, f'Got unexpected SEQ {seq} expected {next_seq}'
            next_seq = calc_next_seq(seq)

            if len_read != 0:
                data += await reader.readexactly(len_read)

    return data, next_seq


async def run_connection_test(
        host: str,
        port: int,
        username: str,
        password: str,
        database: t.Optional[str] = None,
        charset: str = 'utf8mb4',
        query: str = 'SELECT 1'
):
    reader, writer = await aio.open_connection(host=host, port=port)
    response, next_seq = await read(0, reader)
    print()

    print('Read Server Handshake')
    auth_data = interpret_server_handshake(response)
    print()

    response = client_handshake_41(auth_data, username, password, database, charset)
    next_seq = await write(response, next_seq, writer)
    print('Sent Client Handshake')
    print()

    print('Reading server response')
    response, next_seq = await read(next_seq, reader)
    type = interpret_response(response)
    if type == 'err':
        _ = await write(b'\x01', 0, writer)
        print()
        print('Sent Quit')
        print()
        return
    print()

    next_seq = await write(b'\x03' + query.encode(), 0, writer)
    print('Sent Query')
    print('Query:', query)
    print()

    print('Reading Response')
    response, next_seq = await read(next_seq, reader)
    if interpret_response(response) == 'err':
        _ = await write(b'\x01', 0, writer)
        print()
        print('Sent Quit')
        print()
        return

    num_cols, _ = read_lenenc(response)
    num_cols = int.from_bytes(num_cols, byteorder=ENID)
    print('Column Count:     ', num_cols)
    print()

    print('Reading Column Data')
    for i in range(0, num_cols):
        column_def, next_seq = await read(next_seq, reader)
        for label in [
            'Catalog:         ',
            'Schema:          ',
            'Table (virtual): ',
            'Table (original):',
            'Name (virtual):  ',
            'Name (original): ',
        ]:
            value, column_def = read_lenenc_str(column_def)
            print(label, value)

        value, column_def = read_lenenc_int(column_def)
        print('Field Length:    ', value)

        charset = int.from_bytes(column_def[:2], byteorder=ENID)
        column_length = int.from_bytes(column_def[2:6], byteorder=ENID)
        type = int.from_bytes(column_def[6:7], byteorder=ENID)
        flags = int.from_bytes(column_def[7:9], byteorder=ENID)
        decimals = int.from_bytes(column_def[9:10], byteorder=ENID)

        print('Charset:         ', charset)
        print('Column Length:   ', column_length)
        print('Type:            ', type)
        print('Flags:           ', flags)
        print('Decimals:        ', decimals)
        print()

    print('Reading Row Packets')
    response, next_seq = await read(next_seq, reader)
    while interpret_response(response) != 'eof':
        values = []
        for i in range(0, num_cols):
            if response[0] == 0xfb:
                value = None
                response = response[1:]
                values.append(value)
            else:
                value, response = read_lenenc_str(response)
                values.append(value)
        print('Type: Row Data')
        print('Values:', values)
        response, next_seq = await read(next_seq, reader)

    print()

    print('Waiting')
    await aio.sleep(1)
    print()

    _ = await write(b'\x01', 0, writer)
    print('Sent Quit')
    writer.close()


async def main():
    from argparse import ArgumentParser
    from getpass import getpass

    parser = ArgumentParser()
    parser.add_argument('--host', required=True, type=str, help='Database Host/IP')
    parser.add_argument('--port', required=False, type=int, default=3306, help='Port to connect to (default: 3306)')
    parser.add_argument('--username', required=True, type=str, help='Database user')
    parser.add_argument('--password', required=False, type=str, help='Database user password (prompted if not set)')
    parser.add_argument('--database', required=False, type=str, default=None, help='Database to connect to (optional)')
    parser.add_argument('--query', type=str, default='SELECT 1', help='Query to test (default: SELECT 1)')

    args = parser.parse_args()

    if not args.password:
        args.password = getpass('Input Password: ')

    await run_connection_test(
        args.host,
        args.port,
        args.username,
        args.password,
        database=args.database,
        query=args.query,
    )


if __name__ == '__main__':
    aio.run(main())
