from dataclasses import dataclass
from enum import IntFlag, IntEnum
from hashlib import sha1
from typing import (
    Callable,
    Awaitable,
    Tuple,
    TypeVar,
    Iterable,
    Optional,
    List,
    Union,
    Dict,
)
from zlib import decompress, compress

# ██╗    ██╗██╗██████╗ ███████╗███████╗ ██████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗
# ██║    ██║██║██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗████╗ ████║██╔══██╗╚══██╔══╝
# ██║ █╗ ██║██║██████╔╝█████╗  █████╗  ██║   ██║██████╔╝██╔████╔██║███████║   ██║
# ██║███╗██║██║██╔══██╗██╔══╝  ██╔══╝  ██║   ██║██╔══██╗██║╚██╔╝██║██╔══██║   ██║
# ╚███╔███╔╝██║██║  ██║███████╗██║     ╚██████╔╝██║  ██║██║ ╚═╝ ██║██║  ██║   ██║
#  ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝

T = TypeVar('T')

WRITER = Callable[[bytes], Awaitable[None]]
READER = Callable[[int], Awaitable[bytes]]
WRITER_P = Callable[[int, bytes], Awaitable[None]]
READER_P = Callable[[], Awaitable[Tuple[bool, int, bytes]]]

MAX_PACKET = 16777215


def to_int(value: bytes) -> int:
    return int.from_bytes(
        value,
        byteorder='little',
        signed=False,
    )


def to_bytes(length: int, value: int) -> bytes:
    return int.to_bytes(
        value,
        length=length,
        byteorder='little',
        signed=False,
    )


def take(value: bytes, n: int, f: Callable[[bytes], T]) -> Tuple[T, bytes]:
    return f(value[:n]), value[n:]


def next_seq(seq: int) -> int:
    return (seq + 1) % 256


def split(data: bytes) -> Iterable[bytes]:
    view = memoryview(data)
    length = len(view)
    for i in range(0, length, MAX_PACKET):
        yield view[i:i + MAX_PACKET]
    if length % MAX_PACKET == 0:
        yield b''


async def read_message(reader: READER_P, expected_seq: int) -> Tuple[int, bytes]:
    output = bytearray()
    last = False
    while not last:
        last, seq, data = await reader()
        if seq != expected_seq:
            raise ValueError(
                'Unexpected sequence!'
                f'\n expected: {expected_seq}'
                f'\n got:      {seq}'
            )
        expected_seq = next_seq(seq)
        output.extend(data)
    return expected_seq, output


async def write_message(writer: WRITER_P, seq: int, data: bytes) -> int:
    for part in split(data):
        await writer(seq, part)
        seq = next_seq(seq)
    return seq


def create_packet_reader(read: READER) -> READER_P:
    async def read_packet():
        length, data = take(await read(4), 3, to_int)
        seq = to_int(data)
        return length < MAX_PACKET, seq, await read(length)

    return read_packet


def create_packet_writer(drain: WRITER) -> WRITER_P:
    async def write_packet(seq: int, body: bytes):
        out = bytearray(to_bytes(3, len(body)))
        out.extend(to_bytes(1, seq))
        out.extend(body)
        await drain(out)

    return write_packet


class ProtoPlain:
    seq: int

    def __init__(
            self,
            writer: WRITER,
            reader: READER,
    ):
        self.seq = 0
        self.writer = create_packet_writer(writer)
        self.reader = create_packet_reader(reader)

    def reset(self) -> None:
        self.seq = 0

    async def send(self, data: bytes) -> None:
        self.seq = await write_message(
            self.writer,
            self.seq,
            data,
        )

    async def recv(self) -> bytes:
        self.seq, output = await read_message(
            self.reader,
            self.seq,
        )
        return output


def create_compressed_packet_reader(read: READER) -> READER_P:
    async def read_packet():
        length, data = take(await read(7), 3, to_int)
        seq, data = take(data, 1, to_int)
        uncompressed_length = to_int(data)
        data = await read(length)
        if uncompressed_length > 0:
            data = decompress(data)
            if len(data) != uncompressed_length:
                raise ValueError('Compression length mismatch')
        return length < MAX_PACKET, seq, data

    return read_packet


def create_compressed_packet_writer(drain: WRITER, threshold: int) -> WRITER_P:
    async def write_packet(seq: int, body: bytes):
        length = len(body)
        if length > threshold:
            uncompressed_length = len(body)
            body = compress(body)
            length = len(body)
        else:
            uncompressed_length = 0
        out = bytearray(to_bytes(3, length))
        out.extend(to_bytes(1, seq))
        out.extend(to_bytes(3, uncompressed_length))
        out.extend(body)
        await drain(out)

    return write_packet


class ProtoCompressed(ProtoPlain):
    seq_compressed: int

    def __init__(
            self,
            writer: WRITER,
            reader: READER,
            threshold: int = 50,
    ):
        super(ProtoCompressed, self).__init__(
            self.write,
            self.read,
        )
        self.seq_compressed = 0
        self.read_buffer = bytearray()
        self.write_buffer = bytearray()
        self.writer_compressed = create_compressed_packet_writer(
            writer,
            threshold,
        )
        self.reader_compressed = create_compressed_packet_reader(
            reader,
        )

    def reset(self):
        super(ProtoCompressed, self).reset()
        self.seq_compressed = 0

    async def send(self, data: bytes):
        await super(ProtoCompressed, self).send(data)
        self.seq_compressed = await write_message(
            self.writer_compressed,
            self.seq_compressed,
            self.write_buffer,
        )
        self.write_buffer.clear()

    async def send_compressed(self, data: bytes):
        self.seq_compressed = await write_message(
            self.writer_compressed,
            self.seq_compressed,
            data,
        )

    async def recv_compressed(self):
        self.seq_compressed, output = await read_message(
            self.reader_compressed,
            self.seq_compressed,
        )
        self.read_buffer.extend(output)

    async def write(self, data: bytes):
        self.write_buffer.extend(data)

    async def read(self, n: int):
        buffer = self.read_buffer
        if len(buffer) < n:
            await self.recv_compressed()
        if len(buffer) < n:
            raise EOFError('Not enough data')
        data = buffer[:n]
        self.read_buffer = buffer[n:]
        return data


#  ██████╗ ██████╗ ███╗   ██╗███████╗████████╗ █████╗ ████████╗███╗   ██╗████████╗███████╗
# ██╔════╝██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝████╗  ██║╚══██╔══╝██╔════╝
# ██║     ██║   ██║██╔██╗ ██║███████╗   ██║   ███████║   ██║   ██╔██╗ ██║   ██║   ███████╗
# ██║     ██║   ██║██║╚██╗██║╚════██║   ██║   ██╔══██║   ██║   ██║╚██╗██║   ██║   ╚════██║
# ╚██████╗╚██████╔╝██║ ╚████║███████║   ██║   ██║  ██║   ██║   ██║ ╚████║   ██║   ███████║
#  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝   ╚═╝   ╚══════╝

RS_NULL = 0xfb


class Capabilities(IntFlag):
    MYSQL = 1  # Old Long password, assumed set by MySQL after 4.1.1
    FOUND_ROWS = 1 << 1
    LONG_FLAG = 1 << 2
    CONNECT_WITH_DB = 1 << 3
    NO_SCHEMA = 1 << 4
    COMPRESS = 1 << 5
    ODBC = 1 << 6
    LOCAL_FILES = 1 << 7
    IGNORE_SPACE = 1 << 8
    PROTOCOL_41 = 1 << 9
    INTERACTIVE = 1 << 10
    SSL = 1 << 11
    IGNORE_SIGPIPE = 1 << 12
    TRANSACTIONS = 1 << 13
    RESERVED = 1 << 14
    SECURE_CONNECTION = 1 << 15
    MULTI_STATEMENTS = 1 << 16
    MULTI_RESULTS = 1 << 17
    PS_MULTI_RESULTS = 1 << 18
    PLUGIN_AUTH = 1 << 19
    CONNECT_ATTRS = 1 << 20
    PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21
    CAN_HANDLE_EXPIRED_PASSWORDS = 1 << 22
    SESSION_TRACK = 1 << 23
    DEPRECATE_EOF = 1 << 24
    OPTIONAL_RESULTSET_METADATA = 1 << 25
    ZSTD_COMPRESSION_ALGORITHM = 1 << 26
    QUERY_ATTRIBUTES = 1 << 27
    MULTI_FACTOR_AUTHENTICATION = 1 << 28
    CAPABILITY_EXTENSION = 1 << 29
    SSL_VERIFY_SERVER_CERT = 1 << 30
    REMEMBER_OPTIONS = 1 << 31
    # MARIADB
    MARIADB_PROGRESS = 1 << 32
    MARIADB_COM_MULTI = 1 << 33
    MARIADB_STMT_BULK_OPERATIONS = 1 << 34
    MARIADB_EXTENDED_TYPE_INFO = 1 << 35
    MARIADB_CACHE_METADATA = 1 << 36


class ServerStatus(IntFlag):
    IN_TRANS = 1
    AUTOCOMMIT = 1 << 1
    MORE_RESULTS_EXISTS = 1 << 3
    NO_GOOD_INDEX_USED = 1 << 4
    NO_INDEX_USED = 1 << 5
    CURSOR_EXISTS = 1 << 6
    LAST_ROW_SENT = 1 << 7
    DB_DROPPED = 1 << 8
    NO_BACKSLASH_ESCAPES = 1 << 9
    METADATA_CHANGED = 1 << 10
    QUERY_WAS_SLOW = 1 << 11
    PS_OUT_PARAMS = 1 << 12
    IN_TRANS_READONLY = 1 << 13
    SESSION_STATE_CHANGED = 1 << 14


class SendField(IntFlag):
    NOT_NULL = 1
    PRIMARY_KEY = 1 << 1
    UNIQUE_KEY = 1 << 2
    MULTIPLE_KEY = 1 << 3
    BLOB = 1 << 4
    UNSIGNED = 1 << 5
    ZEROFILL = 1 << 6
    BINARY = 1 << 7
    ENUM = 1 << 8
    AUTO_INCREMENT = 1 << 9
    TIMESTAMP = 1 << 10
    SET = 1 << 11
    NO_DEFAULT_VALUE = 1 << 12
    ON_UPDATE_NOW = 1 << 13
    NUM = 1 << 14
    PART_KEY = 1 << 15
    GROUP = 1 << 16
    UNIQUE = 1 << 17
    BINCMP = 1 << 18
    GET_FIXED_FIELDS = 1 << 18
    IN_PART_FUNC = 1 << 19
    IN_ADD_INDEX = 1 << 20
    IS_RENAMED = 1 << 21
    STORAGE_MEDIA = 1 << 22
    STORAGE_MEDIA_MASK = 3 << STORAGE_MEDIA
    COLUMN_FORMAT = 1 << 24
    COLUMN_FORMAT_MASK = 3 << COLUMN_FORMAT
    IS_DROPPED = 1 << 26
    EXPLICIT_NULL = 1 << 27
    NOT_SECONDARY = 1 << 28
    IS_INVISIBLE = 1 << 29


class Response(IntEnum):
    OK = 0
    INFILE = 251
    EOF = 254
    ERR = 255


class Commands(IntEnum):
    SLEEP = 0
    QUIT = 1
    INIT_DB = 2
    QUERY = 3
    FIELD_LIST = 4
    CREATE_DB = 5
    DROP_DB = 6
    REFRESH = 7
    SHUTDOWN = 8
    STATISTICS = 9
    PROCESS_INFO = 10
    CONNECT = 11
    PROCESS_KILL = 12
    DEBUG = 13
    PING = 14
    TIME = 15
    DELAYED_INSERT = 16
    CHANGE_USER = 17
    BINLOG_DUMP = 18
    TABLE_DUMP = 19
    CONNECT_OUT = 20
    REGISTER_SLAVE = 21
    STMT_PREPARE = 22
    STMT_EXECUTE = 23
    STMT_SEND_LONG_DATA = 24
    STMT_CLOSE = 25
    STMT_RESET = 26
    SET_OPTION = 27
    STMT_FETCH = 28
    DAEMON = 29
    BINLOG_DUMP_GTID = 30
    RESET_CONNECTION = 31
    CLONE = 32
    SUBSCRIBE_GROUP_REPLICATION_STREAM = 33
    END = 34


class FieldTypes(IntEnum):
    DECIMAL = 0
    TINY = 1
    SHORT = 2
    LONG = 3
    FLOAT = 4
    DOUBLE = 5
    NULL = 6
    TIMESTAMP = 7
    LONGLONG = 8
    INT24 = 9
    DATE = 10
    TIME = 11
    DATETIME = 12
    YEAR = 13
    NEWDATE = 14
    VARCHAR = 15
    BIT = 16
    TIMESTAMP2 = 17
    DATETIME2 = 18
    TIME2 = 19
    TYPED_ARRAY = 20
    INVALID = 243
    BOOL = 244
    JSON = 245
    NEWDECIMAL = 246
    ENUM = 247
    SET = 248
    TINY_BLOB = 249
    MEDIUM_BLOB = 250
    LONG_BLOB = 251
    BLOB = 252
    VAR_STRING = 253
    STRING = 254
    GEOMETRY = 255


# ██████╗  █████╗ ████████╗ █████╗ ████████╗██╗   ██╗██████╗ ███████╗███████╗
# ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗╚══██╔══╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔════╝
# ██║  ██║███████║   ██║   ███████║   ██║    ╚████╔╝ ██████╔╝█████╗  ███████╗
# ██║  ██║██╔══██║   ██║   ██╔══██║   ██║     ╚██╔╝  ██╔═══╝ ██╔══╝  ╚════██║
# ██████╔╝██║  ██║   ██║   ██║  ██║   ██║      ██║   ██║     ███████╗███████║
# ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝     ╚══════╝╚══════╝

class Reader:
    _data: bytes
    _encoding: str

    __slots__ = ('_data', '_encoding')

    def __init__(self, data: bytes, encoding: str = 'utf-8'):
        self._data = data
        self._encoding = encoding

    def __len__(self):
        return len(self._data)

    def __bool__(self):
        return bool(self._data)

    def __bytes__(self):
        return bytes(self._data)

    def _to_string(self, value: bytes):
        return value.decode(encoding=self._encoding)

    def _read_lenenc_int(self) -> int:
        data = self._data
        size = data[0]
        if size < 0xfb:
            value = data[:1]
            data = data[1:]
        elif size == 0xfc:  # 2 Byte
            value = data[1:3]
            data = data[3:]
        elif size == 0xfd:  # 3 Byte
            value = data[1:4]
            data = data[4:]
        elif size == 0xfe:  # 8 Byte
            value = data[1:9]
            data = data[9:]
        else:
            raise ValueError('unknown lenenc type')
        self._data = data
        return to_int(value)

    def _splice(self, length: int) -> bytes:
        data = self._data
        value = data[:length]
        self._data = data[length:]
        return value

    def int_lenenc(self) -> int:
        return self._read_lenenc_int()

    def bytes_lenenc(self) -> bytes:
        return self._splice(self.int_lenenc())

    def bytes_null(self) -> bytes:
        data = self._data
        value, _, data = data.partition(b'\x00')
        self._data = data
        return value

    def bytes_eof(self) -> bytes:
        return self.remaining()

    def str_lenenc(self) -> str:
        return self._to_string(self.bytes_lenenc())

    def str_null(self) -> str:
        return self._to_string(self.bytes_null())

    def str_eof(self) -> str:
        return self._to_string(self.bytes_eof())

    def remaining(self) -> bytes:
        value = self._data
        self._data = bytes()
        return value

    def bytes(self, length: int) -> bytes:
        return self._splice(length)

    def str(self, length: int) -> str:
        return self._to_string(self.bytes(length))

    def int(self, length: int) -> int:
        return to_int(self._splice(length))


class Writer:
    _data: bytearray
    _encoding: str

    __slots__ = ('_data', '_encoding')

    def __init__(self, encoding='utf-8'):
        self._encoding = encoding
        self._data = bytearray()

    def __len__(self):
        return len(self._data)

    def __bool__(self):
        return bool(self._data)

    def __bytes__(self):
        return bytes(self._data)

    def _to_bytes(self, value: str):
        return value.encode(self._encoding)

    def _write_lenenc_int(self, value: int):
        data = bytearray()
        if value < 0xfb:
            data.extend(to_bytes(1, value))
        elif value < 65535:  # 2 Byte
            data.extend(to_bytes(1, 0xfc))
            data.extend(to_bytes(2, value))
        elif value < 16777215:  # 3 Byte
            data.extend(to_bytes(1, 0xfd))
            data.extend(to_bytes(3, value))
        else:  # 8 Byte
            data.extend(to_bytes(1, 0xfe))
            data.extend(to_bytes(8, value))
        self._data.extend(data)

    def int_lenenc(self, value: int):
        self._write_lenenc_int(value)

    def bytes_lenenc(self, value: bytes):
        self._write_lenenc_int(len(value))
        self._data.extend(value)

    def bytes_null(self, value: bytes):
        self._data.extend(value)
        self._data.append(0)

    def bytes_eof(self, value: bytes):
        self._data.extend(value)

    def str_lenenc(self, value: str):
        self.bytes_lenenc(self._to_bytes(value))

    def str_null(self, value: str):
        self.bytes_null(self._to_bytes(value))

    def str_eof(self, value: str):
        self.bytes_eof(self._to_bytes(value))

    def bytes(self, length: int, value: bytes):
        if len(value) > length:
            raise ValueError('Value too long')
        self._data.extend(value)

    def str(self, length: int, value: str):
        self.bytes(length, self._to_bytes(value))

    def int(self, length: int, value: int):
        self._data.extend(to_bytes(length, value))


class NullSafeReader(Reader):

    def int_lenenc(self) -> Optional[int]:
        if self._data[0] == RS_NULL:
            self._data = self._data[1:]
            return None
        else:
            return super().int_lenenc()

    def bytes_lenenc(self) -> Optional[bytes]:
        size = self.int_lenenc()
        if size is not None:
            return self._splice(size)
        else:
            return None

    def str_lenenc(self) -> Optional[str]:
        data = self.bytes_lenenc()
        if data is not None:
            return self._to_string(data)
        else:
            return None


class NullSafeWriter(Writer):

    def int_lenenc(self, value: Optional[int]):
        if value is not None:
            super().int_lenenc(value)
        else:
            self._data.append(RS_NULL)

    def bytes_lenenc(self, value: Optional[bytes]):
        if value is not None:
            super().bytes_lenenc(value)
        else:
            self._data.append(RS_NULL)

    def str_lenenc(self, value: Optional[str]):
        if value is not None:
            super().str_lenenc(value)
        else:
            self._data.append(RS_NULL)


#  █████╗ ██╗   ██╗████████╗██╗  ██╗███████╗███╗   ██╗████████╗██╗ ██████╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
# ██╔══██╗██║   ██║╚══██╔══╝██║  ██║██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
# ███████║██║   ██║   ██║   ███████║█████╗  ██╔██╗ ██║   ██║   ██║██║     ███████║   ██║   ██║██║   ██║██╔██╗ ██║
# ██╔══██║██║   ██║   ██║   ██╔══██║██╔══╝  ██║╚██╗██║   ██║   ██║██║     ██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
# ██║  ██║╚██████╔╝   ██║   ██║  ██║███████╗██║ ╚████║   ██║   ██║╚██████╗██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
# ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝

def native_password(password: str, auth_data: bytes):
    auth_data = auth_data[:20]  # Discard one extra byte
    password = password.encode('utf-8')
    password = bytes(
        a ^ b
        for a, b in
        zip(
            sha1(password).digest(),
            sha1(auth_data + sha1(sha1(password).digest()).digest()).digest()
        )
    )
    return password


# ██████╗  █████╗  ██████╗██╗  ██╗███████╗████████╗███████╗
# ██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝╚══██╔══╝██╔════╝
# ██████╔╝███████║██║     █████╔╝ █████╗     ██║   ███████╗
# ██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝     ██║   ╚════██║
# ██║     ██║  ██║╚██████╗██║  ██╗███████╗   ██║   ███████║
# ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝

@dataclass
class EOFPacket:
    header: int
    warnings: Optional[int]
    status_flags: Optional[ServerStatus]


@dataclass
class OKPacket:
    header: int
    affected_rows: int
    last_insert_id: int
    status_flags: ServerStatus
    warnings: int
    info: str
    session_state_info: Optional[bytes]


@dataclass
class ERRPacket:
    header: int
    code: int
    state_marker: Optional[str]
    state: Optional[str]
    error: str


class Packets:
    QUERY = bytes([Commands.QUERY])
    PING = bytes([Commands.PING])
    QUIT = bytes([Commands.QUIT])
    RESET = bytes([Commands.RESET_CONNECTION])


class MySQLPacketFactory:
    _capabilities: Capabilities

    def __init__(self, capabilities: Capabilities):
        self._capabilities = capabilities

    def parse_ok(self, data: bytes):
        capabilities = self._capabilities
        reader = Reader(data)
        if len(data) > 7:
            p = OKPacket(
                header=reader.int(1),
                affected_rows=reader.int_lenenc(),
                last_insert_id=reader.int_lenenc(),
                status_flags=(
                    ServerStatus(reader.int(2))
                    if Capabilities.PROTOCOL_41 in capabilities
                       or Capabilities.TRANSACTIONS in capabilities
                    else
                    ServerStatus(0)
                ),
                warnings=(
                    reader.int(2)
                    if Capabilities.PROTOCOL_41 in capabilities else
                    0
                ),
                info=(
                    reader.str_lenenc()
                    if Capabilities.SESSION_TRACK in capabilities else
                    reader.str_eof()
                ),
                session_state_info=None,
            )
            if Capabilities.SESSION_TRACK in capabilities and ServerStatus.SESSION_STATE_CHANGED in p.status_flags:
                p.session_state_info = reader.bytes_lenenc()
        else:
            p = OKPacket(
                header=reader.int(1),
                affected_rows=reader.int_lenenc(),
                last_insert_id=reader.int_lenenc(),
                status_flags=(
                    ServerStatus(reader.int(2))
                    if Capabilities.PROTOCOL_41 in capabilities
                       or Capabilities.TRANSACTIONS in capabilities
                    else
                    ServerStatus(0)
                ),
                warnings=(
                    reader.int(2)
                    if Capabilities.PROTOCOL_41 in capabilities else
                    0
                ),
                info='',
                session_state_info=None,
            )
        return p

    def parse_err(self, data: bytes):
        capabilities = self._capabilities
        reader = Reader(data)
        if Capabilities.PROTOCOL_41 in capabilities:
            return ERRPacket(
                header=reader.int(1),
                code=reader.int(2),
                state_marker=reader.str(1),
                state=reader.str(5),
                error=reader.str_eof(),
            )
        else:
            return ERRPacket(
                header=reader.int(1),
                code=reader.int(2),
                state_marker=None,
                state=None,
                error=reader.str_eof(),
            )

    def parse_eof(self, data: bytes):
        capabilities = self._capabilities
        reader = Reader(data)
        if Capabilities.PROTOCOL_41 in capabilities:
            return EOFPacket(
                header=reader.int(1),
                warnings=reader.int(2),
                status_flags=ServerStatus(reader.int(2)),
            )
        else:
            return EOFPacket(
                header=reader.int(1),
                warnings=None,
                status_flags=None,
            )

    def try_parse_response(self, data: bytes):
        capabilities = self._capabilities
        header = data[0]
        if header == Response.EOF and len(data) < 9:
            if Capabilities.DEPRECATE_EOF in capabilities:
                return Response.OK, self.parse_ok(data)
            else:
                return Response.EOF, self.parse_eof(data)
        elif header == Response.OK:
            return Response.OK, self.parse_ok(data)
        elif header == Response.ERR:
            return Response.ERR, self.parse_err(data)
        return None, data


def is_ack(type: Response):
    return type == Response.OK or type == Response.EOF


# ██╗  ██╗ █████╗ ███╗   ██╗██████╗ ███████╗██╗  ██╗ █████╗ ██╗  ██╗███████╗
# ██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔════╝
# ███████║███████║██╔██╗ ██║██║  ██║███████╗███████║███████║█████╔╝ █████╗
# ██╔══██║██╔══██║██║╚██╗██║██║  ██║╚════██║██╔══██║██╔══██║██╔═██╗ ██╔══╝
# ██║  ██║██║  ██║██║ ╚████║██████╔╝███████║██║  ██║██║  ██║██║  ██╗███████╗
# ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝

@dataclass
class HandshakeV10:
    server_version: str
    thread_id: int
    auth_data_1: bytes
    filler: int
    capabilities: Capabilities
    charset: int
    status: ServerStatus
    auth_data_length: int
    reserved: bytes
    auth_data_2: Optional[bytes]
    auth_plugin_name: Optional[str]

    @property
    def auth_data(self):
        return self.auth_data_1 + self.auth_data_2


@dataclass
class HandshakeResponse41:
    client_flag: Capabilities
    max_packet: int
    charset: int
    filler: bytes
    username: str
    auth_response: bytes
    database: Optional[str] = None
    client_plugin_name: Optional[str] = None
    attrs_length: Optional[int] = None
    attrs: Optional[Dict[str, str]] = None
    compression_level: Optional[int] = None


def parse_handshake(data: bytes):
    reader = Reader(data)
    protocol_version = reader.int(1)
    if protocol_version != 10:
        raise ValueError(
            'Unknown protocol'
            'expected: 10'
            f'got:    {protocol_version}'
        )
    server_version = reader.str_null()
    thread_id = reader.int(4)
    auth_plugin_data_1 = reader.bytes(8)
    filler = reader.int(1)
    cap_lower = reader.int(2)
    charset = reader.int(1)
    status = ServerStatus(reader.int(2))
    cap_upper = reader.int(2)
    capabilities = Capabilities((cap_upper << 16) | cap_lower)
    if Capabilities.PLUGIN_AUTH in capabilities:
        auth_plugin_data_len = reader.int(1)
    else:
        auth_plugin_data_len = 0
    reserved = reader.bytes(6)
    if Capabilities.MYSQL in capabilities:
        reserved += reader.bytes(4)
    else:
        capabilities |= Capabilities(reader.int(4) << 32)
    if Capabilities.PLUGIN_AUTH in capabilities:
        auth_plugin_data_2 = reader.bytes(max((13, auth_plugin_data_len - 8)))
        auth_plugin_name = reader.str_null()
    else:
        auth_plugin_data_2 = None
        auth_plugin_name = None
    if reader.remaining():
        raise ValueError('Remaining handshake data')
    return HandshakeV10(
        server_version=server_version,
        thread_id=thread_id,
        auth_data_1=auth_plugin_data_1,
        filler=filler,
        capabilities=capabilities,
        charset=charset,
        status=status,
        auth_data_length=auth_plugin_data_len,
        reserved=reserved,
        auth_data_2=auth_plugin_data_2,
        auth_plugin_name=auth_plugin_name,
    )


def encode_handshake_response(p: HandshakeResponse41):
    writer = Writer()
    writer.int(4, p.client_flag)
    writer.int(4, p.max_packet)
    writer.int(1, p.charset)
    writer.bytes(23, p.filler)
    writer.str_null(p.username)
    if Capabilities.PLUGIN_AUTH_LENENC_CLIENT_DATA in p.client_flag:
        writer.bytes_lenenc(p.auth_response)
    else:
        size = len(p.auth_response)
        writer.int(1, size)
        writer.bytes(size, p.auth_response)
    if p.database is not None:
        writer.str_null(p.database)
    if p.client_plugin_name is not None:
        writer.bytes_null(p.client_plugin_name.encode('utf-8'))
    if p.attrs_length is not None:
        writer.int_lenenc(p.attrs_length)
    if p.attrs:
        for k, v in p.attrs.items():
            writer.str_lenenc(k)
            writer.str_lenenc(v)
    if p.compression_level:
        writer.int(1, p.compression_level)
    return bytes(writer)


class ProtoHandshake(ProtoPlain):
    initialized = False

    async def recv(self):
        if not self.initialized:
            self.initialized = True
            last, seq, data = await self.reader()
            self.seq = next_seq(seq)
            if not last:
                data += await super(ProtoHandshake, self).recv()
            return data
        else:
            return await super(ProtoHandshake, self).recv()


# ███╗   ███╗██╗   ██╗███████╗ ██████╗ ██╗
# ████╗ ████║╚██╗ ██╔╝██╔════╝██╔═══██╗██║
# ██╔████╔██║ ╚████╔╝ ███████╗██║   ██║██║
# ██║╚██╔╝██║  ╚██╔╝  ╚════██║██║▄▄ ██║██║
# ██║ ╚═╝ ██║   ██║   ███████║╚██████╔╝███████╗
# ╚═╝     ╚═╝   ╚═╝   ╚══════╝ ╚══▀▀═╝ ╚══════╝

class ProtoMySQL:
    MAX_PACKET = int(2 ** 24 - 1)
    CHARSETS = {
        'utf8mb4': 255
    }

    _wire: ProtoPlain
    _factory: MySQLPacketFactory

    server_handshake: HandshakeV10
    handshake_response: HandshakeResponse41

    _compressed: bool
    _threshold: int
    _level: int

    capabilities: Capabilities

    capabilities_server: Capabilities
    capabilities_client: Capabilities

    def __init__(
            self,
            writer: WRITER,
            reader: READER,
            compressed: bool = False,
            threshold: int = 50,
    ):
        self._compressed = compressed
        self._threshold = threshold
        self._writer = writer
        self._reader = reader
        self._wire = ProtoHandshake(self._writer, self._reader)

    def _initialize_capabilities(self):
        self.capabilities_client = (
                Capabilities.PROTOCOL_41
                | Capabilities.SECURE_CONNECTION
                | Capabilities.DEPRECATE_EOF
                | Capabilities.COMPRESS
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
        self.server_handshake = p
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
            auth_response=native_password(password, self.server_handshake.auth_data),
            client_plugin_name='mysql_native_password',
            database=database,
        )

        self.handshake_response = p

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

    async def read(self):
        data = await self._wire.recv()
        type, data = self._factory.try_parse_response(data)
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


# █████╗  ███████╗███████╗██╗   ██╗██╗  ████████╗███████╗███████╗████████╗
# ██╔══██╗██╔════╝██╔════╝██║   ██║██║  ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
# ██████╔╝█████╗  ███████╗██║   ██║██║     ██║   ███████╗█████╗     ██║
# ██╔══██╗██╔══╝  ╚════██║██║   ██║██║     ██║   ╚════██║██╔══╝     ██║
# ██║  ██║███████╗███████║╚██████╔╝███████╗██║   ███████║███████╗   ██║
# ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚══════╝   ╚═╝

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
    type, response = await proto.read()
    if type is None:
        return await parse_result_set(proto, response)
    else:
        return response


# ██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗ █████╗ ██████╗ ██╗     ███████╗
# ██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔══██╗██╔══██╗██║     ██╔════╝
# ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║███████║██████╔╝██║     █████╗
# ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══██║██╔══██╗██║     ██╔══╝
# ██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║██║  ██║██████╔╝███████╗███████╗
# ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝

if __name__ == '__main__':
    from argparse import ArgumentParser
    from getpass import getpass
    from asyncio import StreamReader, StreamWriter, wait_for, run, sleep, open_connection


    def create_stream_reader(stream: StreamReader, timeout: float) -> READER:
        async def read(n: int):
            return await wait_for(stream.readexactly(n), timeout=timeout)

        return read


    def create_stream_writer(stream: StreamWriter, timeout: float) -> WRITER:
        async def drain(data: bytes):
            stream.write(data)
            return await wait_for(stream.drain(), timeout=timeout)

        return drain


    def split_flags_str(i: IntFlag):
        r = repr(i).lstrip('<').rstrip('>')
        if '.' in r:
            r = r.split('.', 1)[1]
        if '|' in r:
            r = r.split('|', 1)[1]
        if ':' in r:
            r = r.split(':', 1)[0]
        return r.split('|')


    def interpret_server_handshake(p: HandshakeV10):
        print('------BASIC------')
        print('Protocol version:', 10)
        print('Server version:  ', p.server_version)
        print('Connection id:   ', p.thread_id)
        print('Auth data 1:     ', p.auth_data_1.hex())
        print('Capabilities:    ', )
        for flag in split_flags_str(p.capabilities):
            print(' -', flag)
        print('Charset:         ', p.charset)
        print('Status flags:    ', )
        for flag in split_flags_str(p.status):
            print(' -', flag)
        if Capabilities.PLUGIN_AUTH in p.capabilities:
            print('-------OPT-------')
            print('Auth data length:', p.auth_data_length)
            print('Auth data 2:     ', p.auth_data_2.hex())
            print('Auth plugin name:', p.auth_plugin_name)


    def interpret_client_handshake(p: HandshakeResponse41):
        print('------BASIC------')
        print('Capabilities:    ', )
        for flag in split_flags_str(p.client_flag):
            print(' -', flag)
        print('Max Packet:      ', p.max_packet)
        print('Charset:         ', p.charset)
        print('Username:        ', p.username)
        print('Auth Response:   ', p.auth_response.hex())
        print('Database:        ', p.database)
        print('Plugin:          ', p.client_plugin_name)


    def interpret_response(p):
        if isinstance(p, OKPacket):
            print('Type: OK')
            print('Affected rows: ', p.affected_rows)
            print('Last Insert id:', p.last_insert_id)
            print('Status:        ', )
            for flag in split_flags_str(p.status_flags):
                print(' -', flag)
            print('Warning:       ', p.warnings)
            print('Info:          ', p.info)
        elif isinstance(p, EOFPacket):
            print('Type: EOF')
        elif isinstance(p, ERRPacket):
            print('Type: ERR')
            print('Code:   ', p.code)
            print('Marker: ', p.state_marker)
            print('State:  ', p.state)
            print('Error:  ', p.error)
            raise ValueError()
        else:
            print('Type: OTHER')
            print(p)


    def interpret_result(rs: ResultSet):
        print('Columns:         ', len(rs.columns))

        for col in rs.columns:
            print('\nCatalog:         ', col.catalog)
            print('Schema:          ', col.schema)
            print('Table (virtual): ', col.table_virtual)
            print('Table (original):', col.table_original)
            print('Name (virtual):  ', col.name_virtual)
            print('Name (original): ', col.name_original)
            print('Charset:         ', col.charset)
            print('Column Length:   ', col.length)
            print('Type:            ', col.type)
            print('Flags:           ', )
            for flag in split_flags_str(col.flags):
                print(' -', flag)
            print('Decimals:        ', col.decimals)

        print('\nRow Packets')
        for row in rs.values:
            print('Values:', row)


    async def run_connection_test(
            host: str,
            port: int,
            username: str,
            password: str,
            database: Optional[str] = None,
            charset: str = 'utf8mb4',
            query: str = 'SELECT 1',
            compressed: bool = True,
    ):
        reader, writer = await open_connection(host=host, port=port)

        proto = ProtoMySQL(
            create_stream_writer(writer, 2),
            create_stream_reader(reader, 2),
            compressed=compressed,
        )

        try:
            data = await proto.connect(
                username=username,
                password=password,
                database=database,
                charset=charset,
            )
        finally:
            print('\nServer handshake')
            interpret_server_handshake(proto.server_handshake)

            print('\nClient response')
            interpret_client_handshake(proto.handshake_response)

        print('\nConnect response')
        interpret_response(data)

        print('\nCommand: PING')
        data = await proto.ping()
        print('\nReceived response')
        interpret_response(data)

        print('\nQuery:', query)
        rs = await standard_query(proto, query)

        print('\nResult Set')
        interpret_result(rs)

        print('\nCommand: RESET')
        data = await proto.reset()
        print('\nReceived response')
        interpret_response(data)

        print('\nWaiting')
        await sleep(1)

        print('\nCommand: QUIT')
        await proto.quit()

        writer.close()


    async def main():
        parser = ArgumentParser()
        parser.add_argument(
            '--host',
            required=True,
            type=str,
            help='Database Host/IP',
        )
        parser.add_argument(
            '--port',
            required=False,
            type=int,
            default=3306,
            help='Port to connect to (default: 3306)',
        )
        parser.add_argument(
            '--username',
            required=True,
            type=str,
            help='Database user',
        )
        parser.add_argument(
            '--password',
            required=False,
            type=str,
            help='Database user password (prompted if not set)',
        )
        parser.add_argument(
            '--database',
            required=False,
            type=str,
            default=None,
            help='Database to connect to (optional)',
        )
        parser.add_argument(
            '--query',
            type=str,
            default='SELECT 1',
            help='Query to test (default: SELECT 1)',
        )
        parser.add_argument(
            '--compressed',
            action='store_true',
            help='Use compression (default: False)',
        )

        args = parser.parse_args()

        if not args.password:
            args.password = getpass('Input Password: ')

        await run_connection_test(
            args.host,
            args.port,
            args.username,
            args.password,
            database=args.database,
            query=args.query,
            compressed=args.compressed,
        )


    run(main())
