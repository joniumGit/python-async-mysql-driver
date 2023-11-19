from dataclasses import dataclass
from typing import Optional

from .constants import Response, ServerStatus, Capabilities, Commands
from .datatypes import Reader


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


class Packets:
    QUERY = bytes([Commands.QUERY])
    PING = bytes([Commands.PING])
    QUIT = bytes([Commands.QUIT])
    RESET = bytes([Commands.RESET_CONNECTION])


class MySQLPacketFactory:
    _capabilities: Capabilities
    _encoding: str

    def __init__(
            self,
            capabilities: Capabilities,
            encoding: str,
    ):
        self._capabilities = capabilities
        self._encoding = encoding

    def parse_ok(self, data: bytes):
        capabilities = self._capabilities
        reader = Reader(data, self._encoding)
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
        reader = Reader(data, self._encoding)
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
        reader = Reader(data, self._encoding)
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

    def parse_infile(self, data: bytes):
        reader = Reader(data, self._encoding)
        return InfilePacket(
            header=reader.int(1),
            filename=reader.str_eof(),
        )

    def try_parse_response(
            self,
            data: bytes,
            include_infile: bool = False,
    ):
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
        elif include_infile and header == Response.INFILE:
            return Response.INFILE, self.parse_infile(data)
        return None, data
