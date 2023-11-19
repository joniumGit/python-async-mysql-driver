from .common import next_seq
from .plain import ProtoPlain


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
