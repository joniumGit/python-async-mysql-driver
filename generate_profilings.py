import cProfile
from asyncio import open_connection, run
from secrets import token_hex

from protocol.application import MySQL
from protocol.async_support import create_stream_reader, create_stream_writer


async def setup(mysql: MySQL):
    await mysql.query('DROP DATABASE IF EXISTS garbage')
    await mysql.query('CREATE DATABASE garbage')
    await mysql.query(
        'CREATE TABLE garbage.garbage ('
        '   id INTEGER AUTO_INCREMENT PRIMARY KEY,'
        '   value TEXT'
        ')'
    )


async def teardown(mysql: MySQL):
    await mysql.query('DROP DATABASE IF EXISTS garbage')


async def run_profile_select(mysql: MySQL, n: int, sort: str):
    perf = cProfile.Profile()
    perf.enable()

    for _ in range(n):
        await mysql.query('SELECT * FROM garbage.garbage limit 10000')

    perf.disable()
    perf.print_stats(sort)


async def run_profile_insert(mysql: MySQL, n: int, sort: str):
    inserts = [
        'INSERT INTO garbage.garbage (value) VALUES '
        + ','.join(f"('{token_hex(1024)}')" for _ in range(10_000))
        for _ in range(n)
    ]

    perf = cProfile.Profile()
    perf.enable()

    for stmt in inserts:
        await mysql.query(stmt)

    perf.disable()
    perf.print_stats(sort)


async def create_connection(**kwargs):
    reader, writer = await open_connection(
        host='127.0.0.1',
        port=3306,
    )

    total_bytes = {
        'in': 0,
        'out': 0,
    }

    writer_s = create_stream_writer(writer, 2)
    reader_s = create_stream_reader(reader, 2)

    async def read(n: int):
        total_bytes['in'] += n
        return await reader_s(n)

    async def drain(data: bytes):
        total_bytes['out'] += len(data)
        await writer_s(data)

    mysql = MySQL(drain, read)

    await mysql.connect(
        username='root',
        password='local',
        **kwargs,
    )

    return mysql, writer.close, total_bytes


async def run_tests(n: int, sort: str, label: str, **kwargs):
    mysql, close, totals = await create_connection(**kwargs)

    try:
        await setup(mysql)

        print(f'\n\nINSERT ({label})')
        await run_profile_insert(mysql, n, sort)

        print(f'\n\nSELECT ({label})')
        await run_profile_select(mysql, n, sort)

        print('Totals')
        print('- IN:  ', totals['in'] / (1024 ** 2), 'MB')
        print('- OUT: ', totals['out'] / (1024 ** 2), 'MB')
    finally:
        await teardown(mysql)


async def main(
        n: int = 1,
        sort: str = 'time',
):
    await run_tests(
        n,
        sort,
        'plain',
        use_compression=False,
    )

    await run_tests(
        n,
        sort,
        'compressed',
        use_compression=True,
        compression_level=1,
    )

    await run_tests(
        n,
        sort,
        'compressed, level=9',
        use_compression=True,
        compression_level=9,
    )


if __name__ == '__main__':
    run(main())
