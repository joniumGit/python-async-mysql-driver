from dataclasses import dataclass
from typing import List, Union, Dict

from .charsets import PYTHON_CHARSETS_FROM_CODE
from .constants import FieldTypes, SendField, Commands
from .datatypes import Reader, NullSafeReader, Writer
from .lifecycle import ProtoMySQLBase


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
class Row:
    names: Dict[str, int]
    data: List[Union[str, None]]

    def __getitem__(self, item):
        if isinstance(item, int):
            return self.data[item]
        else:
            return self.data[self.names[item]]


@dataclass
class ResultSet:
    columns: List[Column]
    rows: List[Row]


def decode(value: Union[bytes, None], charset: str):
    if value is not None:
        return value.decode(charset)
    else:
        return None


class ProtoMySQLResults(ProtoMySQLBase):

    def create_query(self, stmt: str):
        writer = Writer(self._charset)
        writer.int(1, Commands.QUERY)
        writer.str_eof(stmt)
        return bytes(writer)

    async def send_query(self, stmt: str):
        await self.send(self.create_query(stmt))

    async def read_columns(self, columns: int):
        for _ in range(columns):
            data = await self.read_data()
            reader = Reader(data, self._charset)
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

    async def read_values(self, columns: List[Column]):
        data = await self.read_data()
        while data is not None:
            reader = NullSafeReader(data, self._charset)
            yield [
                decode(reader.bytes_lenenc(), PYTHON_CHARSETS_FROM_CODE[col.charset])
                if col.charset in PYTHON_CHARSETS_FROM_CODE else
                reader.bytes_lenenc()
                for col in columns
            ]
            data = await self.read_data()

    async def parse_result_set(self, response: bytes):
        reader = Reader(response, self._charset)
        num_cols = reader.int_lenenc()
        columns = [
            value
            async for value in self.read_columns(num_cols)
        ]
        names = {
            column.name_virtual: i
            for i, column in enumerate(columns)
        }
        rs = ResultSet(
            columns,
            [
                Row(
                    names,
                    value,
                )
                async for value in self.read_values(columns)
            ],
        )
        return rs

    async def standard_query(self, stmt: str):
        await self.send_query(stmt)
        type, response = await self.read(include_infile=True)
        if type is None:
            return await self.parse_result_set(response)
        else:
            return response
