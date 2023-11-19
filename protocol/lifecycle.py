from asyncio import StreamReader, StreamWriter

from .async_support import create_stream_reader, create_stream_writer
from .authentication import native_password
from .constants import Capabilities, Response
from .handshake import HandshakeResponse41, HandshakeV10, parse_handshake, encode_handshake_response
from .packets import MySQLPacketFactory, Packets
from .wire import ProtoPlain, ProtoCompressed, ProtoHandshake


def is_ack(type: Response):
    return type == Response.OK or type == Response.EOF


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
            timeout: float = 2,
            threshold: int = 50,
    ):
        self._compressed = compressed
        self._threshold = threshold
        self._writer = create_stream_writer(writer, timeout)
        self._reader = create_stream_reader(reader, timeout)
        self._wire = ProtoHandshake(self._writer, self._reader)

    def _initialize_capabilities(self):
        self.capabilities_client = (
                Capabilities.PROTOCOL_41
                | Capabilities.SECURE_CONNECTION
                | Capabilities.DEPRECATE_EOF
                | Capabilities.COMPRESS
            # | Capabilities.SESSION_TRACK
        )
        capabilities = self.capabilities_client & self.capabilities_server
        self._factory = MySQLPacketFactory(capabilities)
        self.capabilities = capabilities
        return capabilities

    def _initialize_wire(self):
        if Capabilities.COMPRESS in self.capabilities:
            self._wire = ProtoCompressed(
                self._writer,
                self._reader,
                self._threshold,
            )
        else:
            self._wire = ProtoPlain(
                self._writer,
                self._reader,
            )

    async def _recv_handshake(self):
        data = await self._wire.recv()
        p = parse_handshake(data)
        self._handshake = p
        self.capabilities_server = p.capabilities

    async def _send_handshake_response(
            self,
            username: str,
            password: str,
            database: str,
            charset: str,

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

        await self._wire.send(encode_handshake_response(p))

        # This should still be a non-compressed packet
        response = await self.read_ack()

        # Initialize compression at this stage if required
        self._initialize_wire()

        return response

    async def connect(
            self,
            username: str,
            password: str,
            database: str = None,
            charset: str = 'utf8mb4',
    ):
        await self._recv_handshake()
        return await self._send_handshake_response(
            username,
            password,
            database,
            charset,
        )

    async def read(self, include_infile: bool = False):
        data = await self._wire.recv()
        type, data = self._factory.try_parse_response(data, include_infile)
        if type == Response.ERR:
            raise ValueError(data)
        else:
            return type, data

    async def read_data(self):
        type, data = await self.read()
        if type is not None:
            if is_ack(type):
                return None
            else:
                raise TypeError(data)
        return data

    async def read_ack(self):
        type, data = await self.read()
        if is_ack(type):
            return data
        else:
            raise TypeError(data)

    async def send(self, data: bytes):
        self._wire.reset()
        await self._wire.send(data)

    async def ping(self):
        await self.send(Packets.PING)
        return await self.read_ack()

    async def reset(self):
        await self.send(Packets.RESET)
        return await self.read_ack()

    async def quit(self):
        await self.send(Packets.QUIT)
