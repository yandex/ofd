# coding: utf8

import array
import crcmod
import crcmod.predefined
import decimal
import struct

SIGNATURE = array.array('B', [42, 8, 65, 10]).tostring()


class InvalidProtocolSignature(RuntimeError):
    pass


class Byte(object):
    STRUCT = struct.Struct('B')

    def __init__(self, name, desc):
        self.name = name
        self.desc = desc
        self.maxlen = self.STRUCT.size

    def pack(self, data):
        return self.STRUCT.pack(data)

    def unpack(self, data):
        return self.STRUCT.unpack(data)[0]


class U32(object):
    def __init__(self, name):
        self.name = name
        self.maxlen = 4

    @staticmethod
    def pack(data):
        return struct.pack('<I', data)

    @staticmethod
    def unpack(data):
        return struct.unpack('<I', data)[0]


class String(object):
    def __init__(self, name, desc, maxlen):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen

    @staticmethod
    def pack(value):
        return struct.pack('{}s'.format(len(value)), value.encode('cp866'))

    def unpack(self, data):
        if len(data) == 0:
            return ''
        if len(data) > self.maxlen:
            raise ValueError('String actual size is greater than maximum')
        return struct.unpack('{}s'.format(len(data)), data)[0].decode('cp866')


class UnixTime(object):
    def __init__(self, name):
        self.name = name
        self.maxlen = 4

    @staticmethod
    def pack(time):
        return struct.pack('<I', int(time))

    @staticmethod
    def unpack(data):
        return struct.unpack('<I', data)[0]


class VLN(object):
    def __init__(self, name, maxlen=8):
        self.name = name
        self.maxlen = maxlen

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('VLN actual size is greater than maximum')
        return struct.unpack('<Q', data + b'\x00' * (8 - len(data)))[0]


class FVLN(object):
    def __init__(self, name, maxlen):
        self.name = name
        self.maxlen = maxlen

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('FVLN actual size is greater than maximum')

        pad = b'\x00' * (9 - len(data))
        pos, num = struct.unpack('<bQ', data + pad)
        d = decimal.Decimal(10) ** +pos
        q = decimal.Decimal(10) ** -pos
        return (decimal.Decimal(num) / d).quantize(q)


class STLV(object):
    def __init__(self, name, desc, maxlen):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen

    @staticmethod
    def pack(data):
        return data

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('STLV actual size is greater than maximum')

        result = []
        while len(data) > 0:
            ty, length = struct.unpack('<HH', data[:4])
            doc = DOCUMENTS[ty]
            value = doc.unpack(data[4:4 + length])

            result.append({'name': doc.name, 'value': value, 'tag': ty})
            data = data[4 + length:]

        return result


class SessionHeader(object):
    MAGIC_ID, PVERS_ID, PVERA_ID = range(3)
    MAGIC, = struct.unpack('<I', bytearray.fromhex('2a08410a'))
    PVERS, = struct.unpack('<H', bytearray.fromhex('81a2'))
    PVERA, = struct.unpack('<H', bytearray.fromhex('0001'))
    STRUCT = struct.Struct('<IHH16sHHH')

    def __init__(self, fn_id, length, flags, crc):
        # Номер ФН.
        self.fn_id = fn_id
        self.length = length
        self.flags = flags
        self.crc = crc

    def pack(self):
        return self.STRUCT.pack(
            self.MAGIC,
            self.PVERS,
            self.PVERA,
            self.fn_id,
            self.length,
            self.flags,
            self.crc
        )

    @classmethod
    def unpack_from(cls, data):
        if len(data) != cls.STRUCT.size:
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
        return 'SessionHeader(ps_version={:#x}, pa_version={:#x}, \
fn_id="{}", length={}, flags={:#b}, crc={})'.format(
            self.PVERS,
            self.PVERA,
            self.fn_id,
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

    def pack(self):
        return self.STRUCT.pack(
            self.length,
            self.crc,
            self.MSGTYPE,
            self.doctype,
            self.version,
            self.extra1,
            self.devnum,
            self.docnum,
            self.extra2
        )

    @classmethod
    def unpack_from(cls, data):
        if len(data) != cls.STRUCT.size:
            raise ValueError('data size must be 32')
        pack = cls.STRUCT.unpack(data)

        if pack[cls.MSGTYPE_ID] != cls.MSGTYPE:
            raise ValueError('invalid message type')
        if pack[cls.VERSION_ID] != cls.VERSION:
            raise ValueError('invalid protocol version')

        return FrameHeader(pack[0], pack[1], pack[3], *pack[5:])

    def recalculate_crc(self, body):
        f = crcmod.predefined.mkPredefinedCrcFun('crc-ccitt-false')
        pack = self.pack()
        self.crc = f(pack[:2] + pack[4:] + body)

    def __str__(self):
        return 'FrameHeader(length={}, crc={}, msgtype="{}", doctype={}, \
version={}, extra1={}, devnum={}, docnum={}, extra2={})'.format(
            self.length,
            self.crc,
            self.MSGTYPE,
            self.doctype,
            self.version,
            self.extra1,
            self.devnum,
            self.docnum,
            self.extra2
        )


DOCUMENTS = {
    1: STLV(u'fiscalReport', u'Отчёт о фискализации', maxlen=658),
    3: STLV(u'receipt', u'Кассовый чек', maxlen=32768),
    7: STLV(u'<unknown>', u'Подтверждение оператора', maxlen=362),
    1001: Byte(u'autoMode', u'Автоматический режим'),
    1002: Byte(u'offlineMode', u'Автономный режим'),
    1003: String(u'<unknown>', u'Адрес банковского агента', maxlen=256),
    1004: String(u'<unknown>', u'Адрес банковского субагента', maxlen=256),
    1005: String(u'operatorAddress', u'Адрес оператора по переводу денежных средств', maxlen=256),
    1006: String(u'<unknown>', u'Адрес платежного агента', maxlen=256),
    1007: String(u'<unknown>', u'Адрес платежного субагента', maxlen=256),
    1008: String(u'buyerAddress', u'Адрес покупателя', maxlen=64),
    1009: String(u'retailPlaceAddress', u'Адрес расчетов', maxlen=256),
    1010: VLN(u'Размер вознаграждения банковского агента (субагента)'),
    1011: VLN(u'Размер вознаграждения платежного агента (субагента)'),
    1012: UnixTime(u'Время, дата'),
    1013: String(u'kktNumber', u'Заводской номер ККТ', maxlen=10),
    1014: String(u'<unknown>', u'Значение типа строка', maxlen=64),
    1015: U32(u'Значение типа целое'),
    1016: String(u'operatorInn', u'ИНН оператора по переводу денежных средств', maxlen=12),
    1017: String(u'ofdInn', u'ИНН ОФД', maxlen=12),
    1018: String(u'userInn', u'ИНН пользователя', maxlen=12),
    1019: String(u'<unknown>', u'Информационное cообщение', maxlen=64),
    1020: VLN(u'ИТОГ'),
    1021: String(u'operator', u'Кассир', maxlen=64),
    1022: Byte(u'<unknown>', u'Код ответа ОФД'),
    1023: FVLN(u'Количество', maxlen=8),
    1024: String(u'<unknown>', u'Наименование банковского агента', maxlen=64),
    1025: String(u'<unknown>', u'Наименование банковского субагента', maxlen=64),
    1026: String(u'operatorName', u'Наименование оператора по переводу денежных средств', 64),
    1027: String(u'<unknown>', u'Наименование платежного агента', maxlen=64),
    1028: String(u'<unknown>', u'Наименование платежного субагента', maxlen=64),
    1029: String(u'<unknown>', u'Наименование реквизита', maxlen=64),
    1030: String(u'name', u'Наименование товара', maxlen=64),
    1031: VLN(u'Наличными'),
    1032: STLV(u'<unknown>', u'Налог', maxlen=33),
    1033: STLV(u'<unknown>', u'Налоги', maxlen=33),
    1034: FVLN(u'Наценка (ставка)', maxlen=8),
    1035: VLN(u'Наценка (сумма)'),
    1036: String(u'machineNumber', u'Номер автомата', maxlen=12),
    1037: String(u'kktRegId', u'Номер ККТ', maxlen=20),
    1038: U32(u'Номер смены'),
    1039: String(u'<unknown>', u'Зарезервирован', maxlen=12),
    1040: U32(u'Номер фискального документа'),
    1041: String(u'fiscalDriveNumber', desc=u'Заводской номер фискального накопителя', maxlen=16),
    1042: U32(u'Номер чека'),
    1043: VLN(u'Общая стоимость позиции с учетом скидок и наценок'),
    1044: String(u'bankAgentOperation', u'Операция банковского агента', maxlen=24),
    1045: String(u'bankSubagentOperation', u'операция банковского субагента', maxlen=24),
    1046: String(u'<unknown>', u'ОФД', maxlen=64),
    1047: STLV(u'<unknown>', u'Параметр настройки', maxlen=144),
    1048: String(u'user', u'Пользователь', maxlen=64),
    1049: String(u'<unknown>', u'Почтовый индекс', maxlen=6),
    1050: Byte(u'fiscalDriveExhaustionSign', u'Признак исчерпания ресурса ФН'),
    1051: Byte(u'fiscalDriveReplaceRequiredSign', u'Признак необходимости срочной замены ФН'),
    1052: Byte(u'fiscalDriveMemoryExceededSign', u'Признак переполнения памяти ФН'),
    1053: Byte(u'ofdResponseTimeoutSign', u'Признак превышения времени ожидания ответа ОФД'),
    1054: Byte(u'operationType', u'Признак расчета'),
    1055: Byte(u'<unknown>', u'Признак системы налогообложения'),
    1056: Byte(u'encryptionSign', u'Признак шифрования'),
    1057: Byte(u'<unknown>', u'Применение платежными агентами (субагентами)'),
    1058: Byte(u'<unknown>', u'Применение банковскими агентами (субагентами)'),
    1059: STLV(u'items', u'наименование товара (реквизиты)', maxlen=132),
    1060: String(u'<unknown>', u'Сайт налогового органа', maxlen=64),
    1061: String(u'<unknown>', u'Сайт ОФД', maxlen=64),
    1062: Byte(u'taxationType', u'системы налогообложения'),  # TODO: Bitfields actually, read more.
    1063: FVLN(u'Скидка (ставка)', 8),
    1064: VLN(u'Скидка (сумма)'),
    1065: String(u'<unknown>', u'Сокращенное наименование налога', maxlen=10),
    1066: String(u'message', u'Сообщение', maxlen=256),
    1067: STLV(u'<unknown>', u'Сообщение оператора для ККТ', maxlen=216),
    1068: STLV(u'<unknown>', u'Сообщение оператора для ФН', maxlen=169),
    1069: STLV(u'message', u'Сообщение оператору', maxlen=328),
    1070: FVLN(u'Ставка налога', maxlen=5),
    1071: STLV(u'stornoItems', u'сторно товара (реквизиты)', maxlen=132),
    1072: VLN(u'Сумма налога', maxlen=8),
    1073: String(u'bankAgentPhone', u'Телефон банковского агента', maxlen=19),
    1074: String(u'paymentAgentPhone', u'Телефон платежного агента', maxlen=19),
    1075: String(u'<unknown>', u'Телефон оператора по переводу денежных средств', maxlen=19),
    1076: String(u'type', u'Тип сообщения', maxlen=64),
    1077: String(u'fiscalSign', u'Фискальный признак документа', maxlen=6),
    1078: String(u'<unknown>', u'Фискальный признак оператора', maxlen=18),
    1079: VLN(u'Цена за единицу'),
    1080: String(u'barcode', u'Штриховой код EAN13', maxlen=16),
    1081: VLN(u'Электронными'),
    1082: String(u'bankSubagentPhone', u'Телефон банковского субагента', maxlen=19),
    1083: String(u'paymentSubagentPhone', u'Телефон платежного субагента', maxlen=19),
    1084: STLV(u'<unknown>', u'Дополнительный реквизит', maxlen=328),
    1085: String(u'key', u'Наименование дополнительного реквизита', maxlen=64),
    1086: String(u'value', u'Значение дополнительного реквизита', maxlen=256),

    # 1087: u'Итог смены',
    1117: String(u'senderAddress', 'адрес отправителя', 64),
}
