import struct
from typing import Any


class DIDCoding:
    def __init__(self, size: int,factor:float,offset:float):
        self._did_len = int(size)
        self._factor=float(factor)
        self._offset=float(offset)

    @property
    def factor(self):
        return self._factor

    @factor.setter
    def factor(self,value):
        self._factor =float(value)

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self,value):
        self._offset =float(value)

    def encode(self, phy_value):
        pass

    def decode(self, inr_value):
        pass

    def __len__(self) -> int:
        return self._did_len


class AsciiCoding(DIDCoding):
    def __init__(self, string_len: int):
        self._did_len = int(string_len)
        self._factor=1
        self._offset=1

    def encode(self, string_ascii: Any) -> bytes:  # type: ignore
        if not isinstance(string_ascii, str):
            raise ValueError("AsciiCodec requires a string for encoding")

        if len(string_ascii) != self._did_len:
            raise ValueError('String must be %d long' % self._did_len)

        return string_ascii.encode('ascii')

    def decode(self, string_bin: list) -> Any:
        string_ascii = bytes(string_bin).decode('ascii')
        if len(string_ascii) != self._did_len:
            raise ValueError(
                'Trying to decode a string of %d bytes but codec expects %d bytes' % (len(string_ascii), self._did_len))
        return string_ascii

class UCharLinearCoding(DIDCoding):
    def __init__(self, factor: float, offset: float):
        self._factor=float(factor)
        self._offset=float(offset)

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self._did_len:
            raise Exception("input value not equal the setting value" + str(self._did_len))
        val = list(struct.unpack(">B", bytes(inr_value)))[0]
        return val * self.factor + self.offset

    def encode(self, phy_value) -> list:
        phy_value = int((phy_value - self.offset) / self.factor)
        bt = list(struct.pack(">B", phy_value))
        return bt


class CharLinearCoding(DIDCoding):
    def __init__(self, factor: float, offset: float):
        self._factor=float(factor)
        self._offset=float(offset)

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self._did_len:
            raise Exception("CharLinearCoding function inr_value not equal the setting value" + str(self._did_len))
        val = list(struct.unpack(">b", bytes(inr_value)))
        return val * self.factor + self.offset

    def encode(self, phy_value) -> list:
        phy_value = int((phy_value - self.offset) / self.factor)
        bt = list(struct.pack(">b", phy_value))
        return bt


class UShortLinearCoding(DIDCoding):
    def __init__(self, factor: float, offset: float):
        self._factor=float(factor)
        self._offset=float(offset)

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self._did_len:
            raise Exception("UShortLinearCoding function inr_value not equal the setting value" + str(self._did_len))
        val = list(struct.unpack(">" + ("H" * int(self._did_len / 2)), bytes(inr_value)))[0]
        return val * self.factor + self.offset

    def encode(self, phy_value) -> list:
        phy_value = int((phy_value - self.offset) / self.factor)
        bt = list(struct.pack(">H", phy_value))
        return bt


class ShortLinearCoding(DIDCoding):
    def __init__(self, factor: float, offset: float):
        self._factor=float(factor)
        self._offset=float(offset)

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self._did_len:
            raise Exception("UShortLinearCoding function inr_value not equal the setting value" + str(self._did_len))
        val = list(struct.unpack(">h", bytes(inr_value)))[0]
        return val * self.factor + self.offset

    def encode(self, phy_value) -> list:
        phy_value = int((phy_value - self.offset) / self.factor)
        bt = list(struct.pack(">h", phy_value))
        return bt


class DIDList():
    dict = {
        0xf191: AsciiCoding(17),  # 车架号
        0x0021: UCharLinearCoding(0.5, 0),  # 油门开度%
        0x0041: CharLinearCoding(0.2, 0),  # 电池电压V
        0x0051: UShortLinearCoding(0.1, 0),  # 发动机转速rpm
        0x0061: ShortLinearCoding(0.01, 0)  # 车速km/h
    }
    value = {
        0xf191: "FVB30FKA034ALDFA0",
        0x0021: 100,
        0x0041: 24,
        0x0051: 1220,
        0x0061: 220,
    }
