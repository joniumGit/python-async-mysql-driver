from dataclasses import dataclass
from typing import List, Union

from .constants import FieldTypes, SendField, Commands
from .datatypes import Reader, NullSafeReader, Writer
from .lifecycle import ProtoMySQL


@dataclass
class Column:
    catalog: str
    schema: str
    table_original: str
    table_virtual: str
    name_virtual: str
    name_original: str
    fixed: int
    charset: int
    length: int
    type: FieldTypes
    flags: SendField
    decimals: int


@dataclass
class ResultSet:
    columns: List[Column]
    values: List[List[Union[str, None]]]


def create_query(stmt: str):
    writer = Writer()
    writer.int(1, Commands.QUERY)
    writer.str_eof(stmt)
    return bytes(writer)


async def send_query(proto: ProtoMySQL, stmt: str):
    await proto.send(create_query(stmt))


async def read_columns(proto: ProtoMySQL, columns: int):
    for _ in range(columns):
        data = await proto.read_data()
        reader = Reader(data)
        yield Column(
            catalog=reader.str_lenenc(),
            schema=reader.str_lenenc(),
            table_virtual=reader.str_lenenc(),
            table_original=reader.str_lenenc(),
            name_virtual=reader.str_lenenc(),
            name_original=reader.str_lenenc(),
            fixed=reader.int_lenenc(),
            charset=reader.int(2),
            length=reader.int(4),
            type=FieldTypes(reader.int(1)),
            flags=SendField(reader.int(2)),
            decimals=reader.int(1),
        )


async def read_values(proto: ProtoMySQL, columns: int):
    data = await proto.read_data()
    while data is not None:
        reader = NullSafeReader(data)
        yield [
            reader.str_lenenc()
            for _ in range(columns)
        ]
        data = await proto.read_data()


async def parse_result_set(proto: ProtoMySQL, response: bytes):
    reader = Reader(response)
    num_cols = reader.int_lenenc()
    rs = ResultSet(
        [
            value
            async for value in read_columns(proto, num_cols)
        ],
        [
            value
            async for value in read_values(proto, num_cols)
        ],
    )
    return rs


async def standard_query(proto: ProtoMySQL, stmt: str):
    await send_query(proto, stmt)
    type, response = await proto.read(include_infile=True)
    if type is None:
        return await parse_result_set(proto, response)
    else:
        return response


__all__ = [
    'Column',
    'ResultSet',
    'standard_query',
]
