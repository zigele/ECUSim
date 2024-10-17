import struct
from typing import Any


class DIDCoding:
    did_len: int
    factor: float
    offset: float

    def __init__(self, size: int):
        self.did_len = size

    def encode(self, phy_value):
        pass

    def decode(self, inr_value):
        pass

    def __len__(self) -> int:
        return self.did_len


class AsciiCoding(DIDCoding):
    did_len: int
    factor: float
    offset: float

    def __init__(self, string_len: int):
        self.did_len = string_len

    def encode(self, string_ascii: Any) -> bytes:  # type: ignore
        if not isinstance(string_ascii, str):
            raise ValueError("AsciiCodec requires a string for encoding")

        if len(string_ascii) != self.did_len:
            raise ValueError('String must be %d long' % self.did_len)
        return string_ascii.encode('ascii')

    def decode(self, string_bin: list) -> Any:
        string_ascii = bytes(string_bin).decode('ascii')
        if len(string_ascii) != self.did_len:
            raise ValueError(
                'Trying to decode a string of %d bytes but codec expects %d bytes' % (len(string_ascii), self.did_len))
        return string_ascii

    def __len__(self) -> int:
        return self.did_len


class UCharLinearCoding(DIDCoding):
    did_len = 1
    factor: float
    offset: float

    def __init__(self, factor: float, offset: float):
        self.factor = factor
        self.offset = offset

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self.did_len:
            raise Exception("UCharLinearCoding function inr_value not equal the setting value" + str(self.did_len))
        val = list(struct.unpack(">B", bytes(inr_value)))[0]
        return val * self.factor + self.offset

    def encode(self, phy_value) -> list:
        phy_value = int((phy_value - self.offset) / self.factor)
        bt = list(struct.pack(">B", phy_value))
        return bt


class CharLinearCoding(DIDCoding):
    did_len = 1
    factor: float
    offset: float

    def __init__(self, factor: float, offset: float):
        self.factor = factor
        self.offset = offset

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self.did_len:
            raise Exception("CharLinearCoding function inr_value not equal the setting value" + str(self.did_len))
        val = list(struct.unpack(">b", bytes(inr_value)))
        return val * self.factor + self.offset

    def encode(self, phy_value) -> list:
        phy_value = int((phy_value - self.offset) / self.factor)
        bt = list(struct.pack(">b", phy_value))
        return bt


class UShortLinearCoding(DIDCoding):
    did_len = 2
    factor: float
    offset: float

    def __init__(self, factor: float, offset: float):
        self.factor = factor
        self.offset = offset

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self.did_len:
            raise Exception("UShortLinearCoding function inr_value not equal the setting value" + str(self.did_len))
        val = list(struct.unpack(">" + ("H" * int(self.did_len / 2)), bytes(inr_value)))[0]
        return val * self.factor + self.offset

    def encode(self, phy_value) -> list:
        phy_value = int((phy_value - self.offset) / self.factor)
        bt = list(struct.pack(">H", phy_value))
        return bt


class ShortLinearCoding(DIDCoding):
    did_len = 2
    factor: float
    offset: float

    def __init__(self, factor: float, offset: float):
        self.factor = factor
        self.offset = offset

    def decode(self, inr_value: list) -> float:
        if not len(inr_value) == self.did_len:
            raise Exception("UShortLinearCoding function inr_value not equal the setting value" + str(self.did_len))
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
