from enum import IntFlag, IntEnum

ResultNullValue = 0xfb


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
    """Internal
    """

    VARCHAR = 15
    BIT = 16

    TIMESTAMP2 = 17
    """Internal? (Can't find from docs)
    """

    DATETIME2 = 18
    """Internal
    """

    TIME2 = 19
    """Internal
    """

    TYPED_ARRAY = 20
    """Replication only
    """

    INVALID = 243

    BOOL = 244
    """Placeholder
    """

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
