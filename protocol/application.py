from .constants import Capabilities
from .handshake import NativePasswordHandshake
from .packets import CommandPacket, read_ack
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
            use_compression: bool,
            compression_threshold: int = 50,
    ):
        self._writer = writer
        self._reader = reader
        self.charset = 'utf8mb4'
        self.supported_capabilities = (
                Capabilities.PROTOCOL_41
                | Capabilities.SECURE_CONNECTION
                | Capabilities.DEPRECATE_EOF
                | (
                    Capabilities.COMPRESS
                    if use_compression else
                    0
                )
        )
        self.capabilities = self.supported_capabilities
        self.handshake = NativePasswordHandshake(
            self._writer,
            self._reader,
            self.capabilities,
        )
        self.compression_threshold = compression_threshold

    async def connect(
            self,
            username: str,
            password: str,
            charset: str = 'utf8mb4',
            database: str = None,
    ):
        self.charset = charset
        ok, self._charset_python, self.capabilities = await self.handshake.connect(
            username,
            password,
            charset,
            database,
        )
        if Capabilities.COMPRESS in self.capabilities:
            self._wire = ProtoCompressed(
                self._writer,
                self._reader,
                threshold=self.compression_threshold,
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
        await self.send_data(CommandPacket.RESET)
        return await self._ack()

    async def quit(self):
        await self.send_data(CommandPacket.QUIT)

    async def query(self, stmt: str) -> ResultSet:
        self._wire.reset()
        return await self._querier.query(stmt)
