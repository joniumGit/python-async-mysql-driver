from dataclasses import dataclass
from typing import Optional

from ..constants import Capabilities, ServerStatus
from ..datatypes import Reader


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
