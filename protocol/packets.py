from dataclasses import dataclass
from typing import Optional

from .constants import Capabilities, Response, ServerStatus, Commands
from .datatypes import Reader, Writer
from .wire import WireFormat


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


@dataclass
class InfilePacket:
    header: int
    filename: str


class CommandPacket:
    QUERY = bytes([Commands.QUERY])
    PING = bytes([Commands.PING])
    QUIT = bytes([Commands.QUIT])
    RESET_CONNECTION = bytes([Commands.RESET_CONNECTION])


def parse_ok(data: bytes, charset: str, capabilities: Capabilities):
    reader = Reader(data, charset)
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


def parse_err(data: bytes, charset: str, capabilities: Capabilities):
    reader = Reader(data, charset)
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


def parse_eof(data: bytes, charset: str, capabilities: Capabilities):
    reader = Reader(data, charset)
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


def parse_infile(data: bytes, charset: str):
    reader = Reader(data, charset)
    return InfilePacket(
        header=reader.int(1),
        filename=reader.str_eof(),
    )


def try_parse_response(
        data: bytes,
        charset: str,
        capabilities: Capabilities,
        include_infile: bool,
):
    header = data[0]
    if header == Response.EOF and len(data) < 9:
        if Capabilities.DEPRECATE_EOF in capabilities:
            return Response.OK, parse_ok(data, charset, capabilities)
        else:
            return Response.EOF, parse_eof(data, charset, capabilities)
    elif header == Response.OK:
        return Response.OK, parse_ok(data, charset, capabilities)
    elif header == Response.ERR:
        return Response.ERR, parse_err(data, charset, capabilities)
    elif include_infile and header == Response.INFILE:
        return Response.INFILE, parse_infile(data, charset)
    return None, data


def might_be_ack(type: Response):
    return type == Response.OK or type == Response.EOF


def create_change_database_command(
        charset: str,
        database: str,
):
    writer = Writer(charset)
    writer.int(1, Commands.INIT_DB)
    writer.str_eof(database)
    return bytes(writer)


async def read_packet(
        wire: WireFormat,
        charset: str,
        capabilities: Capabilities,
        include_infile: bool = False,
):
    data = await wire.recv()
    type, data = try_parse_response(
        data,
        charset,
        capabilities,
        include_infile,
    )
    if type == Response.ERR:
        raise ValueError(data)
    else:
        return type, data


async def read_data_packet(
        wire: WireFormat,
        charset: str,
        capabilities: Capabilities,
):
    type, data = await read_packet(wire, charset, capabilities)
    if type is None:
        return data
    else:
        raise TypeError(data)


async def read_packets_until_ack(
        wire: WireFormat,
        charset: str,
        capabilities: Capabilities,
):
    type, data = await read_packet(wire, charset, capabilities)
    while type is None:
        yield data
        type, data = await read_packet(wire, charset, capabilities)
    if not might_be_ack(type):
        raise TypeError(data)


async def read_ack(
        wire: WireFormat,
        charset: str,
        capabilities: Capabilities,
):
    type, data = await read_packet(wire, charset, capabilities)
    if might_be_ack(type):
        return data
    else:
        raise TypeError(data)
