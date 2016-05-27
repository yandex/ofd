# coding: utf8

import array
import decimal
import struct


def check_signature(data):
    if array.array('B', data) != array.array('B', [42, 8, 65, 10]):
        raise RuntimeError('invalid protocol signature')


class Byte(object):
    STRUCT = struct.Struct('B')

    def __init__(self, name):
        self.name = name
        self.maxlen = self.STRUCT.size

    def pack(self, data):
        return self.STRUCT.pack(data)

    def unpack(self, data):
        return self.STRUCT.unpack(data)[0]


class VLN(object):
    def __init__(self, name, maxlen=8):
        self.name = name
        self.maxlen = maxlen

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('VLN actual size is greater than maximum')
        return struct.unpack('<Q', data + '\x00' * (8 - len(data)))[0]


class FVLN(object):
    def __init__(self, name, maxlen):
        self.name = name
        self.maxlen = maxlen

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('FVLN actual size is greater than maximum')

        pad = '\x00' * (9 - len(data))
        pos, num = struct.unpack('<bQ', data + pad)
        d = decimal.Decimal(10) ** +pos
        q = decimal.Decimal(10) ** -pos
        return (decimal.Decimal(num) / d).quantize(q)


class SessionHeader(object):
    MAGIC_ID, PVERS_ID, PVERA_ID = range(3)
    MAGIC, = struct.unpack('<I', bytearray.fromhex('2a08410a'))
    PVERS, = struct.unpack('<H', bytearray.fromhex('81a2'))
    PVERA, = struct.unpack('<H', bytearray.fromhex('0001'))
    STRUCT = struct.Struct('<IHH16sHHH')

    def __init__(self, device_id, length, flags, crc):
        self.device_id = device_id
        self.length = length
        self.flags = flags
        self.crc = crc

    def pack(self):
        return self.STRUCT.pack(
            self.MAGIC,
            self.PVERS,
            self.PVERA,
            self.device_id,
            self.length,
            self.flags,
            self.crc
        )

    @classmethod
    def unpack_from(cls, data):
        if len(data) != 30:
            raise ValueError('data size must be 30')
        pack = cls.STRUCT.unpack(data)

        if pack[cls.MAGIC_ID] != cls.MAGIC:
            raise ValueError('invalid protocol signature')
        if pack[cls.PVERS_ID] != cls.PVERS:
            raise ValueError('invalid session protocol version')
        if pack[cls.PVERA_ID] != cls.PVERA:
            raise ValueError('invalid application protocol version')

        return SessionHeader(*pack[cls.PVERA_ID + 1:])

    def __str__(self):
        return 'SessionHeader(ps_version={:#x}, pa_version={:#x}, device_id="{}", length={}, flags={:#b}, crc={})'.format(
            self.PVERS,
            self.PVERA,
            self.device_id,
            self.length,
            self.flags,
            self.crc
        )


class FrameHeader(object):
    MSGTYPE_ID, VERSION_ID = (2, 4)
    MSGTYPE = 0xa5
    VERSION = 1
    STRUCT = struct.Struct('<HHBBB2s8s3s12s')

    def __init__(self, length, crc, doctype, extra1, devnum, docnum, extra2):
        # Длина.
        self.length = length
        # Проверочный код.
        self.crc = crc
        # Тип сообщения протокола.
        self.msgtype = self.MSGTYPE
        # Тип фискального документа.
        self.doctype = doctype
        # Версия протокола.
        self.version = self.VERSION
        # Номер ФН.
        self.devnum = devnum
        # Номер ФД.
        self.docnum = docnum
        # Служебные данные 1.
        self.extra1 = extra1
        # Служебные данные 2.
        self.extra2 = extra2

    @classmethod
    def unpack_from(cls, data):
        if len(data) != 32:
            raise ValueError('data size must be 32')
        pack = cls.STRUCT.unpack(data)

        if pack[cls.MSGTYPE_ID] != cls.MSGTYPE:
            raise ValueError('invalid message type')
        if pack[cls.VERSION_ID] != cls.VERSION:
            raise ValueError('invalid protocol version')

        return FrameHeader(pack[0], pack[1], pack[3], *pack[5:])
