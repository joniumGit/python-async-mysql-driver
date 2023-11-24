import cProfile
import pstats
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
    stats = pstats.Stats(perf).strip_dirs().sort_stats(sort)
    stats.print_stats()
    return stats.total_calls, stats.total_tt


async def run_profile_insert(mysql: MySQL, n: int, sort: str):
    inserts = [
        'INSERT INTO garbage.garbage (value) VALUES '
        + ','.join(f"('{token_hex(1024)}')" for _ in range(10000))
        for _ in range(n)
    ]

    perf = cProfile.Profile()
    perf.enable()

    for stmt in inserts:
        await mysql.query(stmt)

    perf.disable()
    stats = pstats.Stats(perf).strip_dirs().sort_stats(sort)
    stats.print_stats()
    return stats.total_calls, round(stats.total_tt, 2)


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


async def run_tests(
        n: int,
        sort: str,
        label: str,
        output: dict,
        **kwargs,
):
    mysql, close, totals = await create_connection(**kwargs)
    await setup(mysql)
    try:
        out = {
            'insert': {
                'calls': 0,
                'time': 0,
                'in': 0,
                'out': 0,
            },
            'select': {
                'calls': 0,
                'time': 0,
                'in': 0,
                'out': 0,
            },
        }

        print(f'\n\nINSERT ({label})')
        n_calls, t_time = await run_profile_insert(mysql, n, sort)
        out['insert']['calls'] = n_calls
        out['insert']['time'] = t_time
        out['insert']['in'] = totals['in']
        out['insert']['out'] = totals['out']

        print(f'\n\nSELECT ({label})')
        n_calls, t_time = await run_profile_select(mysql, n, sort)
        out['select']['calls'] = n_calls
        out['select']['time'] = t_time
        out['select']['in'] = totals['in'] - out['insert']['in']
        out['select']['out'] = totals['out'] - out['insert']['out']

        print('Totals')
        print('- IN:  ', totals['in'] / (1024 ** 2), 'MB')
        print('- OUT: ', totals['out'] / (1024 ** 2), 'MB')
        output[label] = out
    finally:
        await teardown(mysql)


def print_results(baseline: str, values: dict):
    baseline_values = values[baseline]
    units = {
        'time': 's',
        'in': 'kb',
        'out': 'kb',
        'calls': '',
    }
    for label, dataset in values.items():
        print('DATASET:', label)
        for key in ['select', 'insert']:
            for option in ['time', 'in', 'out', 'calls']:
                bl = baseline_values[key][option]
                cv = dataset[key][option]
                c = (cv - bl) / bl * 100
                if option in ['in', 'out']:
                    cv = cv / 1024
                print(
                    ' -',
                    key,
                    option.ljust(5, ' '),
                    f'({"+" if c > 0 else ""}{c:.2f}%)',
                    cv,
                    units[option],
                )


async def main(
        n: int = 1,
        sort: str = 'time',
):
    output = {}

    await run_tests(
        n,
        sort,
        'plain',
        output,
        use_compression=False,
    )

    await run_tests(
        n,
        sort,
        'compressed',
        output,
        use_compression=True,
        compression_level=1,
    )

    await run_tests(
        n,
        sort,
        'compressed, level=9',
        output,
        use_compression=True,
        compression_level=9,
    )

    print('\n\n')
    print_results('plain', output)


if __name__ == '__main__':
    run(main())
