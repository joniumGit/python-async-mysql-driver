import asyncio as aio
from enum import IntFlag
from typing import Optional

from protocol.application import ProtoMySQL
from protocol.constants import Capabilities, SendField, FieldTypes
from protocol.datatypes import Reader, NullSafeReader
from protocol.packets import HandshakeV10, OKPacket, EOFPacket, ERRPacket, HandshakeResponse41


def split_flags_str(i: IntFlag):
    r = repr(i).lstrip('<').rstrip('>')
    if '.' in r:
        r = r.split('.', 1)[1]
    if '|' in r:
        r = r.split('|', 1)[1]
    if ':' in r:
        r = r.split(':', 1)[0]
    return r.split('|')


def interpret_server_handshake(p: HandshakeV10):
    print('------BASIC------')
    print('Protocol version:', 10)
    print('Server version:  ', p.server_version)
    print('Connection id:   ', p.thread_id)
    print('Auth data 1:     ', p.auth_data_1.hex())
    print('Capabilities:    ', )
    for flag in split_flags_str(p.capabilities):
        print(' -', flag)
    print('Charset:         ', p.charset)
    print('Status flags:    ', )
    for flag in split_flags_str(p.status):
        print(' -', flag)
    if Capabilities.PLUGIN_AUTH in p.capabilities:
        print('-------OPT-------')
        print('Auth data length:', p.auth_data_length)
        print('Auth data 2:     ', p.auth_data_2.hex())
        print('Auth plugin name:', p.auth_plugin_name)


def interpret_client_handshake(p: HandshakeResponse41):
    print('------BASIC------')
    print('Capabilities:    ', )
    for flag in split_flags_str(p.client_flag):
        print(' -', flag)
    print('Max Packet:      ', p.max_packet)
    print('Charset:         ', p.charset)
    print('Username:        ', p.username)
    print('Auth Response:   ', p.auth_response.hex())
    print('Database:        ', p.database)
    print('Plugin:          ', p.client_plugin_name)


def interpret_response(p):
    if isinstance(p, OKPacket):
        print('Type: OK')
        print('Affected rows: ', p.affected_rows)
        print('Last Insert id:', p.last_insert_id)
        print('Status:        ', )
        for flag in split_flags_str(p.status_flags):
            print(' -', flag)
        print('Warning:       ', p.warnings)
        print('Info:          ', p.info)
    elif isinstance(p, EOFPacket):
        print('Type: EOF')
    elif isinstance(p, ERRPacket):
        print('Type: ERR')
        print('Code:   ', p.code)
        print('Marker: ', p.state_marker)
        print('State:  ', p.state)
        print('Error:  ', p.error)
        raise ValueError()
    else:
        print('Type: OTHER')
        print(p)


async def parse_result_set(proto: ProtoMySQL, data: bytes):
    reader = Reader(data)
    num_cols = reader.int_lenenc()
    print('Columns:         ', num_cols)
    for i in range(0, num_cols):
        data = await proto.recv_packet()
        reader = Reader(data)
        for label in [
            'Catalog:         ',
            'Schema:          ',
            'Table (virtual): ',
            'Table (original):',
            'Name (virtual):  ',
            'Name (original): ',
        ]:
            value = reader.str_lenenc()
            print(label, value)
        charset = reader.int(2)
        column_length = reader.int(4)
        type = reader.int(1)
        flags = reader.int(2)
        decimals = reader.int(1)
        print('Charset:         ', charset)
        print('Column Length:   ', column_length)
        print('Type:            ', FieldTypes(type))
        print('Flags:           ', )
        for flag in split_flags_str(SendField(flags)):
            print(' -', flag)
        print('Decimals:        ', decimals)
        print()

    print('Reading Row Packets')
    data = await proto.recv_packet()
    while isinstance(data, (bytes, bytearray)):
        reader = NullSafeReader(data)
        values = [
            reader.str_lenenc()
            for _ in range(0, num_cols)
        ]
        print('Type: Row Data')
        print('Values:', values)
        data = await proto.recv_packet()
    print()
    interpret_response(data)


async def run_connection_test(
        host: str,
        port: int,
        username: str,
        password: str,
        database: Optional[str] = None,
        charset: str = 'utf8mb4',
        query: str = 'SELECT 1',
        compressed: bool = True,
):
    reader, writer = await aio.open_connection(host=host, port=port)
    proto = ProtoMySQL(
        writer,
        reader,
        compressed=compressed,
    )

    data = await proto.recv_handshake()
    print('\nReceived handshake')
    interpret_server_handshake(data)

    data = await proto.send_handshake_response(
        username=username,
        password=password,
        database=database,
        charset=charset,
    )
    print('\nSent handshake response')
    interpret_client_handshake(proto._response)

    print('\nReceived response')
    interpret_response(data)

    data = await proto.ping()
    print('\nSent ping')
    print('\nReceived response')
    interpret_response(data)

    data = await proto.query(query)
    print('\nSent Query')
    print('Query:', query)
    print('\nReceived response')
    interpret_response(data)

    print()
    print('Parsing Result Set')
    await parse_result_set(proto, data)
    print()

    print('Waiting')
    await aio.sleep(1)
    print()

    await proto.quit()
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
