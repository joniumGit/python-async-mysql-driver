from .general import parse_eof, parse_ok, parse_infile, parse_err
from ..constants import Capabilities, Response
from ..wire import WireFormat


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


async def read_generic_packet(
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
    type, data = await read_generic_packet(
        wire,
        charset,
        capabilities,
        include_infile=False,
    )
    if type is None:
        return data
    else:
        raise TypeError(data)


async def read_data_packets_until_ack(
        wire: WireFormat,
        charset: str,
        capabilities: Capabilities,
):
    type, data = await read_generic_packet(
        wire,
        charset,
        capabilities,
        include_infile=False,
    )
    while type is None:
        yield data
        type, data = await read_generic_packet(
            wire,
            charset,
            capabilities,
            include_infile=False,
        )
    if not might_be_ack(type):
        raise TypeError(data)


async def read_ack(
        wire: WireFormat,
        charset: str,
        capabilities: Capabilities,
):
    type, data = await read_generic_packet(wire, charset, capabilities)
    if might_be_ack(type):
        return data
    else:
        raise TypeError(data)
