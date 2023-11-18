import asyncio as aio
from enum import IntFlag
from typing import Optional

from protocol.constants import Capabilities
from protocol.handshake import HandshakeV10, HandshakeResponse41
from protocol.lifecycle import ProtoMySQL
from protocol.packets import OKPacket, EOFPacket, ERRPacket
from protocol.resultset import standard_query, ResultSet


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


def interpret_result(rs: ResultSet):
    print('Columns:         ', len(rs.columns))

    for col in rs.columns:
        print('\nCatalog:         ', col.catalog)
        print('Schema:          ', col.schema)
        print('Table (virtual): ', col.table_virtual)
        print('Table (original):', col.table_original)
        print('Name (virtual):  ', col.name_virtual)
        print('Name (original): ', col.name_original)
        print('Charset:         ', col.charset)
        print('Column Length:   ', col.length)
        print('Type:            ', col.type)
        print('Flags:           ', )
        for flag in split_flags_str(col.flags):
            print(' -', flag)
        print('Decimals:        ', col.decimals)

    print('\nRow Packets')
    for row in rs.values:
        print('Values:', *row)


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

    try:
        data = await proto.connect(
            username=username,
            password=password,
            database=database,
            charset=charset,
        )
    finally:
        print('\nServer handshake')
        interpret_server_handshake(proto._handshake)

        print('\nClient response')
        interpret_client_handshake(proto._response)

    print('\nConnect response')
    interpret_response(data)

    print('\nCommand: PING')
    data = await proto.ping()
    print('\nReceived response')
    interpret_response(data)

    print('\nQuery:', query)
    rs = await standard_query(proto, query)

    print('\nResult Set')
    interpret_result(rs)

    print('\nWaiting')
    await aio.sleep(1)

    print('\nCommand: QUIT')
    await proto.quit()

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
