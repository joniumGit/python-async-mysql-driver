import sys
from asyncio import open_connection, run
from pathlib import Path

from protocol.application import ProtoMySQL
from protocol.async_support import create_stream_reader, create_stream_writer


async def collect_data(port: int):
    reader, writer = await open_connection(
        host='127.0.0.1',
        port=port,
    )

    proto = ProtoMySQL(
        create_stream_writer(writer, 2),
        create_stream_reader(reader, 2),
        compressed=True,
    )

    await proto.connect(
        username='root',
        password='local',
        database='information_schema',
        charset='utf8mb4',
    )

    rs = await proto.standard_query(
        """
        SELECT *
        FROM (
            SELECT id                 AS id,
                   character_set_name AS name,
                   character_set_name AS parent
            FROM collations
            WHERE is_default = 'Yes'
            UNION
            SELECT id                 AS id,
                   collation_name     AS name,
                   character_set_name AS parent
            FROM collations
        ) t
        ORDER BY id;
        """
    )

    charsets = {}
    python_charsets = {}

    for result in rs.rows:
        col_id = result['id']
        col_name = result['name']
        col_parent = result['parent']

        if col_parent in ('utf8mb4', 'utf8mb3'):
            col_parent = 'utf8'
        elif col_parent == 'latin1':
            # https://dev.mysql.com/doc/refman/8.0/en/charset-we-sets.html
            col_parent = 'cp1252'
        elif col_parent == 'koi8r':
            # https://docs.python.org/3.8/library/codecs.html#standard-encodings
            col_parent = 'koi8_r'
        elif col_parent == 'koi8u':
            col_parent = 'koi8_u'
        elif col_parent == 'ucs2':
            # https://en.wikipedia.org/wiki/UTF-16
            col_parent = 'utf16'
        elif col_parent == 'utf16le':
            col_parent = 'utf-16-le'

        charsets[col_name] = int(col_id)

        try:
            'a'.encode(col_parent)
            python_charsets[col_name] = col_parent
        except LookupError:
            print('Unsupported', col_name)
            continue

    return charsets, python_charsets


async def main():
    print('MYSQL')
    charsets, python_charsets = await collect_data(3306)
    print('MARIADB')
    charsets_maria, python_charsets_maria = await collect_data(3307)

    charsets.update(charsets_maria)
    python_charsets.update(python_charsets_maria)

    reverse = {}
    for k, v in charsets.items():
        if v not in reverse and k in python_charsets:
            reverse[v] = python_charsets[k]

    reverse_charsets = {}
    for k, v in charsets.items():
        if v not in reverse_charsets:
            reverse_charsets[v] = k
        elif len(reverse_charsets[v]) < len(k):
            reverse_charsets[v] = k

    with open(Path(sys.argv[0]).parent / 'protocol' / 'charsets.py', 'w') as f:
        f.write('CHARSETS = {\n')
        for k, v in charsets.items():
            f.write(f"    '{k}': {v},\n")
        f.write('}\n\n')
        f.write('CHARSETS_REVERSE = {\n')
        for k, v in reverse_charsets.items():
            f.write(f"    {k}: '{v}',\n")
        f.write('}\n\n')
        f.write('PYTHON_CHARSETS = {\n')
        for k, v in python_charsets.items():
            f.write(f"    '{k}': '{v}',\n")
        f.write('}\n\n')
        f.write('PYTHON_CHARSETS_FROM_CODE = {\n')
        for k, v in reverse.items():
            f.write(f"    {k}: '{v}',\n")
        f.write('}\n')


if __name__ == '__main__':
    run(main())
