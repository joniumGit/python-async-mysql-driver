from dataclasses import dataclass
from typing import List, Union, Dict

from .constants import FieldTypes, SendField, Commands, Capabilities
from .datatypes import Reader, NullSafeReader, Writer
from .packets import read_packet, read_packets_until_ack, read_data_packet
from .wire import WireFormat


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


class Querier:

    def __init__(
            self,
            wire: WireFormat,
            charset: str,
            capabilities: Capabilities,
    ):
        self.wire = wire
        self.charset = charset
        self.capabilities = capabilities

    def create_query(self, stmt: str):
        writer = Writer(self.charset)
        writer.int(1, Commands.QUERY)
        writer.str_eof(stmt)
        return bytes(writer)

    async def send_query(self, stmt: str):
        await self.wire.send(self.create_query(stmt))

    async def read_data(self):
        return await read_data_packet(
            self.wire,
            self.charset,
            self.capabilities,
        )

    async def read_columns(self, columns: int):
        for _ in range(columns):
            data = await self.read_data()
            reader = Reader(data, self.charset)
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

    async def read_values(self, columns: int):
        async for data in read_packets_until_ack(
                self.wire,
                self.charset,
                self.capabilities,
        ):
            reader = NullSafeReader(data, self.charset)
            yield [
                reader.str_lenenc()
                for _ in range(columns)
            ]

    async def parse_result_set(self, response: bytes):
        reader = Reader(response, self.charset)
        num_cols = reader.int_lenenc()
        columns = [
            value
            async for value in self.read_columns(num_cols)
        ]
        names = {
            column.name_virtual: i
            for i, column in enumerate(columns)
        }
        rows = [
            Row(
                names,
                value,
            )
            async for value in self.read_values(num_cols)
        ]
        return ResultSet(
            columns=columns,
            rows=rows,
        )

    async def query(self, stmt: str):
        await self.send_query(stmt)
        type, response = await read_packet(
            self.wire,
            self.charset,
            self.capabilities,
            include_infile=True,
        )
        if type is None:
            return await self.parse_result_set(response)
        else:
            return response
