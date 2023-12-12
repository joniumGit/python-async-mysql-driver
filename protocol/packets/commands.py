from ..constants import Commands
from ..datatypes import Writer


class CommandPacket:
    QUERY = bytes([Commands.QUERY])
    PING = bytes([Commands.PING])
    QUIT = bytes([Commands.QUIT])
    RESET_CONNECTION = bytes([Commands.RESET_CONNECTION])


def create_change_database_command(
        charset: str,
        database: str,
):
    writer = Writer(charset)
    writer.int(1, Commands.INIT_DB)
    writer.str_eof(database)
    return bytes(writer)
