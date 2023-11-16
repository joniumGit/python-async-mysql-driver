from typing import Optional


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


class Reader:
    _data: bytes
    _encoding: str

    def __init__(self, data: bytes, encoding: str = 'utf-8'):
        self._data = data
        self._encoding = encoding

    def __len__(self):
        return len(self._data)

    def __bool__(self):
        return bool(self._data)

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

    def __init__(self, encoding='utf-8'):
        self._encoding = encoding
        self._data = bytearray()

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


ResultNullValue = 0xfb


class NullSafeReader(Reader):

    def int_lenenc(self) -> Optional[int]:
        if self._data[0] == ResultNullValue:
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
            self._data.append(ResultNullValue)

    def bytes_lenenc(self, value: Optional[bytes]):
        if value is not None:
            super().bytes_lenenc(value)
        else:
            self._data.append(ResultNullValue)

    def str_lenenc(self, value: Optional[str]):
        if value is not None:
            super().str_lenenc(value)
        else:
            self._data.append(ResultNullValue)


__all__ = [
    'Reader',
    'NullSafeReader',
    'Writer',
    'NullSafeWriter',
]
