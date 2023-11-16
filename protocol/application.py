from asyncio import StreamReader, StreamWriter

from .authentication import native_password
from .constants import Capabilities, Commands
from .packets import MySQLPacketFactory, HandshakeResponse41, HandshakeV10
from .wire import ProtoPlain, ProtoCompressed


class ProtoMySQL:
    MAX_PACKET = int(2 ** 24 - 1)
    CHARSETS = {
        'utf8mb4': 255
    }

    _wire: ProtoPlain
    _factory: MySQLPacketFactory

    _handshake: HandshakeV10
    _response: HandshakeResponse41

    _compressed: bool
    _threshold: int
    _level: int

    capabilities: Capabilities

    capabilities_server: Capabilities
    capabilities_client: Capabilities

    def __init__(
            self,
            writer: StreamWriter,
            reader: StreamReader,
            compressed: bool = False,
            threshold: int = 50,
            level: int = 3,
    ):
        self._compressed = compressed
        self._threshold = threshold
        self._level = level
        self._wire = ProtoPlain(
            writer,
            reader,
        )

    def _initialize_capabilities(self):
        self.capabilities_client = (
                Capabilities.PROTOCOL_41
                | Capabilities.SECURE_CONNECTION
                | Capabilities.DEPRECATE_EOF
                | Capabilities.PLUGIN_AUTH
                | Capabilities.PLUGIN_AUTH_LENENC_CLIENT_DATA
                | Capabilities.COMPRESS
        )
        capabilities = self.capabilities_client & self.capabilities_server
        self._factory = MySQLPacketFactory(capabilities)
        self.capabilities = capabilities
        return capabilities

    def _initialize_compression(self):
        if Capabilities.COMPRESS in self.capabilities:
            self._wire = ProtoCompressed(
                self._wire.writer,
                self._wire.reader,
                self._threshold,
            )

    async def recv_handshake(self):
        # This sets the sequence from next packet
        # Only necessary for handshake
        self._wire.seq = None

        data = await self._wire.recv()
        p = MySQLPacketFactory.parse_handshake(data)
        self._handshake = p
        self.capabilities_server = p.capabilities
        return p

    async def send_handshake_response(
            self,
            username: str,
            password: str,
            database: str = None,
            charset: str = 'utf8mb4',

    ):
        capabilities = self._initialize_capabilities()

        # This is used just for connecting to a DB
        if database is not None:
            if Capabilities.CONNECT_WITH_DB not in self.capabilities_server:
                raise ValueError('CONNECT_WITH_DB not supported')
            else:
                capabilities |= Capabilities.CONNECT_WITH_DB

        p = HandshakeResponse41(
            client_flag=self.capabilities,
            max_packet=self.MAX_PACKET,
            charset=self.CHARSETS[charset],
            filler=b'\x00' * 23,
            username=username,
            auth_response=native_password(password, self._handshake.auth_data),
            client_plugin_name='mysql_native_password',
            database=database,
        )

        self._response = p

        await self._wire.send(self._factory.write_handshake_response(p))

        # This should still be a non-compressed packet
        response = await self.recv_packet()

        # Initialize compression at this stage if required
        self._initialize_compression()

        return response

    async def recv_data(self):
        data = await self._wire.recv()
        p = self._factory.parse_response(data)
        if p is not None:
            return p
        else:
            return data

    async def recv_packet(self):
        data = await self._wire.recv()
        p = self._factory.parse_response(data)
        if p is not None:
            return p
        else:
            return data

    async def query(self, stmt: str):
        self._wire.reset()
        await self._wire.send(self._factory.create_query(stmt))
        return await self.recv_packet()

    async def ping(self):
        self._wire.reset()
        await self._wire.send(bytes([Commands.PING]))
        return await self.recv_packet()

    async def quit(self):
        self._wire.reset()
        await self._wire.send(bytes([Commands.QUIT]))
