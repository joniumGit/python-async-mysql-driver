from .constants import Capabilities
from .handshake import NativePasswordHandshake
from .packets import CommandPacket, read_ack, create_change_database_command
from .text import Querier, ResultSet
from .wire import WireFormat, READER, WRITER, ProtoPlain, ProtoCompressed


class MySQL:
    _writer: WRITER
    _reader: READER
    _wire: WireFormat

    _charset_python: str
    _querier: Querier

    charset: str
    suppoerted_capabilities: Capabilities
    capabilities: Capabilities
    handshake: NativePasswordHandshake

    def __init__(
            self,
            writer: WRITER,
            reader: READER,
    ):
        self._writer = writer
        self._reader = reader
        self.charset = 'utf8mb4'
        self.supported_capabilities = (
                Capabilities.PROTOCOL_41
                | Capabilities.SECURE_CONNECTION
                | Capabilities.DEPRECATE_EOF
                | Capabilities.COMPRESS
        )
        self.capabilities = self.supported_capabilities

    async def connect(
            self,
            username: str,
            password: str,
            charset: str = 'utf8mb4',
            database: str = None,
            use_compression: bool = True,
            compression_threshold: int = 50,
            compression_level: int = 1,
            enable_ssl=None,
    ):
        self.charset = charset
        capabilities = self.supported_capabilities

        if not use_compression:
            capabilities ^= Capabilities.COMPRESS

        self.handshake = NativePasswordHandshake(
            self._writer,
            self._reader,
            capabilities,
        )

        ok, self._charset_python, self.capabilities = await self.handshake.connect(
            username=username,
            password=password,
            charset=charset,
            database=database,
            enable_ssl=enable_ssl,
        )

        if Capabilities.COMPRESS in self.capabilities:
            self._wire = ProtoCompressed(
                self._writer,
                self._reader,
                threshold=compression_threshold,
                level=compression_level,
            )
        else:
            self._wire = ProtoPlain(
                self._writer,
                self._reader
            )

        self._querier = Querier(
            self._wire,
            self._charset_python,
            self.capabilities,
        )

        return ok

    async def send_data(self, data: bytes):
        self._wire.reset()
        await self._wire.send(data)

    async def _ack(self):
        await read_ack(
            self._wire,
            self._charset_python,
            self.capabilities
        )

    async def ping(self):
        await self.send_data(CommandPacket.PING)
        return await self._ack()

    async def reset(self):
        await self.send_data(CommandPacket.RESET_CONNECTION)
        return await self._ack()

    async def change_database(self, database: str):
        await self.send_data(create_change_database_command(
            self._charset_python,
            database,
        ))
        return await self._ack()

    async def quit(self):
        await self.send_data(CommandPacket.QUIT)

    async def query(self, stmt: str) -> ResultSet:
        self._wire.reset()
        return await self._querier.query(stmt)
