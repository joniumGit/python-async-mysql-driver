from asyncio import open_connection
from contextlib import asynccontextmanager
from secrets import token_hex
from typing import Union
from unittest import IsolatedAsyncioTestCase

from .. import MySQL
from ..async_support import create_stream_reader, create_stream_writer
from ..packets import OKPacket
from ..text import ResultSet
from ..wire import MAX_PACKET

LARGE_QUERY = 'SELECT * FROM information_schema.columns'
CREATE_INSERT_DATABASE = 'CREATE DATABASE garbage'
DROP_INSERT_DATABASE = 'DROP DATABASE IF EXISTS garbage'
CREATE_INSERT_TARGET = 'CREATE TABLE garbage (id INTEGER, value TEXT)'
LARGE_INSERT = 'INSERT INTO garbage (id, value) VALUES '


async def assert_large_query_results(mysql: MySQL):
    assert isinstance(await mysql.query(LARGE_QUERY), ResultSet)


async def assert_db_selected(mysql: MySQL, database: Union[str, None]):
    rs = await mysql.query('SELECT DATABASE()')
    assert rs.rows[0][0] == database


class GeneralTests(IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        reader, writer = await open_connection('127.0.0.1', 3306)
        self.close = writer.close
        self.writer = create_stream_writer(writer, 2)
        self.reader = create_stream_reader(reader, 2)
        self.mysql = MySQL(
            self.writer,
            self.reader,
        )

    async def asyncTearDown(self):
        await self.mysql.quit()
        self.close()
        del self.close
        del self.writer
        del self.reader
        del self.mysql

    async def connect(
            self,
            database: Union[str, None] = None,
            **kwargs,
    ):
        await self.mysql.connect(
            username='root',
            password='local',
            database=database,
            **kwargs,
        )
        return self.mysql

    async def test_connecting_without_db(self):
        mysql = await self.connect(
            database=None
        )
        await assert_db_selected(mysql, None)

    async def test_connecting_with_db(self):
        mysql = await self.connect(
            database='information_schema'
        )
        await assert_db_selected(mysql, 'information_schema')

    async def test_connecting_without_db_and_swapping_db(self):
        mysql = await self.connect(
            database=None
        )
        await assert_db_selected(mysql, None)
        await mysql.change_database('information_schema')
        await assert_db_selected(mysql, 'information_schema')

    async def test_connecting_with_db_and_swapping_db(self):
        mysql = await self.connect(
            database='performance_schema'
        )
        await assert_db_selected(mysql, 'performance_schema')
        await mysql.change_database('information_schema')
        await assert_db_selected(mysql, 'information_schema')

    async def test_connection_reset(self):
        mysql = await self.connect()
        rs = await mysql.query('SET @variable = 1')
        assert isinstance(rs, OKPacket)
        rs = await mysql.query('SELECT @variable')
        assert rs.rows[0][0] == '1'
        await mysql.reset()
        rs = await mysql.query('SELECT @variable')
        assert rs.rows[0][0] is None

    async def test_query_large_not_compressed(self):
        await assert_large_query_results(await self.connect(
            use_compression=False,
        ))

    async def test_query_large_compressed_small_threshold(self):
        await assert_large_query_results(await self.connect(
            use_compression=True,
            compression_threshold=0,
        ))

    async def test_query_large_compressed_default_threshold(self):
        await assert_large_query_results(await self.connect(
            use_compression=True,
        ))

    async def test_query_large_compressed_large_threshold(self):
        await assert_large_query_results(await self.connect(
            use_compression=True,
            compression_threshold=MAX_PACKET,
        ))

    @asynccontextmanager
    async def setup_large_inserts(self, mysql: MySQL):
        await mysql.query(DROP_INSERT_DATABASE)
        await mysql.query(CREATE_INSERT_DATABASE)
        await mysql.change_database('garbage')
        await mysql.query(CREATE_INSERT_TARGET)
        yield LARGE_INSERT + ','.join(f"({i}, '{token_hex(1024)}')" for i in range(1, 10_000))
        await mysql.query(DROP_INSERT_DATABASE)

    async def large_inserts(self, mysql: MySQL):
        async with self.setup_large_inserts(mysql) as stmt:
            rs = await mysql.query(stmt)
            assert isinstance(rs, OKPacket)

    async def test_insert_large_not_compressed(self):
        await self.large_inserts(await self.connect(
            use_compression=False,
        ))

    async def test_insert_large_compressed_small_threshold(self):
        await self.large_inserts(await self.connect(
            use_compression=True,
            compression_threshold=0,
        ))

    async def test_insert_large_compressed_default_threshold(self):
        await self.large_inserts(await self.connect(
            use_compression=True,
        ))

    async def test_insert_large_compressed_large_threshold(self):
        await self.large_inserts(await self.connect(
            use_compression=True,
            compression_threshold=MAX_PACKET,
        ))
