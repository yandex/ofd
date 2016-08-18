# coding: utf8

import array
import crcmod
import crcmod.predefined
import decimal
import struct

VERSION = (1, 1, 0, 'ATOL-3')

SIGNATURE = array.array('B', [42, 8, 65, 10]).tostring()


class ProtocolError(RuntimeError):
    pass


class InvalidProtocolSignature(ProtocolError):
    pass


class InvalidProtocolDocument(ProtocolError):
    def __init__(self):
        super(InvalidProtocolDocument, self).__init__('invalid document')


class Byte(object):
    """
    Represents a single-byte document item packer/unpacker.
    """
    STRUCT = struct.Struct('B')

    def __init__(self, name, desc, cardinality=None):
        """
        Initialize a single-byte document item with the given name and description.
        :param name: name as it is encoded in Federal Tax Service.
        :param desc: description as it is specified in OFD protocol.
        :param cardinality: specifies how many times the given document item should appear in the parent document. None
               Possible values: number as a string meaning exact number, '+' meaning one or more, '*' meaning zero or
               more, None meaning that the cardinality is undefined.
        """
        self.name = name
        self.desc = desc
        self.cardinality = cardinality
        self.maxlen = self.STRUCT.size

    def pack(self, data):
        """
        Pack the given value into a byte representation.
        :param data: a single byte value.
        :raise struct.error: if data is not an integer or it does not fit in [0; 255] range.
        :return: packed value as a bytearray.
        >>> Byte('', '').pack(42)
        b'*'
        >>> Byte('', '').pack(256)
        Traceback (most recent call last):
        ...
        struct.error: ubyte format requires 0 <= number <= 255
        >>> Byte('', '').pack('string')
        Traceback (most recent call last):
        ...
        struct.error: required argument is not an integer
        """
        return self.STRUCT.pack(data)

    def unpack(self, data):
        return self.STRUCT.unpack(data)[0]


class U32(object):
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc
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


class ByteArray(object):
    def __init__(self, name, desc, maxlen):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen

    @staticmethod
    def pack(value):
        return struct.pack('{}s'.format(len(value)), value)

    def unpack(self, data):
        if len(data) == 0:
            return ''
        if len(data) > self.maxlen:
            raise ValueError('ByteArray actual size is greater than maximum')
        return struct.unpack('{}s'.format(len(data)), data)[0]


class UnixTime(object):
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc
        self.maxlen = 4

    @staticmethod
    def pack(time):
        return struct.pack('<I', int(time))

    @staticmethod
    def unpack(data):
        return struct.unpack('<I', data)[0]


class VLN(object):
    def __init__(self, name, desc, maxlen=8):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('VLN actual size is greater than maximum')
        return struct.unpack('<Q', data + b'\x00' * (8 - len(data)))[0]


class FVLN(object):
    def __init__(self, name, desc, maxlen):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('FVLN actual size is greater than maximum')

        pad = b'\x00' * (9 - len(data))
        pos, num = struct.unpack('<bQ', data + pad)
        d = decimal.Decimal(10) ** +pos
        q = decimal.Decimal(10) ** -pos
        return float((decimal.Decimal(num) / d).quantize(q))


class STLV(object):
    def __init__(self, name, desc, maxlen, cardinality='1'):
        self.name = name
        self.desc = desc
        self.maxlen = maxlen
        self.cardinality = cardinality

    @staticmethod
    def pack(data):
        return data

    def unpack(self, data):
        if len(data) > self.maxlen:
            raise ValueError('STLV actual size is greater than maximum')

        result = {}

        while len(data) > 0:
            ty, length = struct.unpack('<HH', data[:4])
            doc = DOCUMENTS[ty]
            value = doc.unpack(data[4:4 + length])

            if hasattr(doc, 'cardinality'):
                if doc.cardinality in {'*', '+'}:
                    if doc.name not in result:
                        result[doc.name] = []
                    result[doc.name].append(value)
                else:
                    result[doc.name] = value
            else:
                result[doc.name] = value
            data = data[4 + length:]

        return result


class SessionHeader(object):
    MAGIC_ID, PVERS_ID, PVERA_ID = range(3)
    MAGIC, = struct.unpack('<I', bytearray.fromhex('2a08410a'))
    PVERS, = struct.unpack('<H', bytearray.fromhex('81a2'))
    PVERA = {
        struct.unpack('<H', bytearray.fromhex('0001'))[0],
        struct.unpack('<H', bytearray.fromhex('0002'))[0]
    }
    STRUCT = struct.Struct('<IHH16sHHH')

    def __init__(self, pva, fs_id, length, flags, crc):
        self.pva = pva
        # Номер ФН.
        self.fs_id = fs_id
        self.length = length
        self.flags = flags
        self.crc = crc

    def pack(self):
        return self.STRUCT.pack(
            self.MAGIC,
            self.PVERS,
            struct.unpack('<H', bytearray.fromhex('0001'))[0],
            self.fs_id,
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

        if pack[cls.PVERA_ID] not in cls.PVERA:
            raise ValueError('invalid application protocol version')

        return SessionHeader(pack[cls.PVERA_ID], *pack[cls.PVERA_ID + 1:])

    def __str__(self):
        return 'Заголовок Сообщения сеансового уровня\n' \
               '{:24}: {:#010x}\n' \
               '{:24}: {:#06x}\n' \
               '{:24}: {:#06x}\n' \
               '{:24}: {}\n' \
               '{:24}: {}\n' \
               '{:24}: {:#b}\n' \
               '{:24}: {}'.format(
                    'Сигнатура', self.MAGIC,
                    'Версия S-протокола', self.PVERS,
                    'Версия A-протокола', self.pva,
                    'Номер ФН', self.fs_id,
                    'Размер тела', self.length,
                    'Флаги', self.flags,
                    'Проверочный код (CRC)', self.crc)


class FrameHeader(object):
    MSGTYPE_ID, VERSION_ID = (2, 4)
    MSGTYPE = 0xa5
    VERSION = 1
    STRUCT = struct.Struct('<HHBBB2s8s3s12s')
    STRUCT_TINY = struct.Struct('<BBB2s8s3s12s')

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
        self._docnum = docnum
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
            self._docnum,
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

    @classmethod
    def unpack_from_raw(cls, data):
        """
        Unpack container header directly from bytearray without `length` and `CRC` fields.
        :param data: container header.
        :return: structured ContainerHeader.
        """
        if len(data) != cls.STRUCT_TINY.size:
            raise ValueError('data size must be 28')
        pack = cls.STRUCT_TINY.unpack(data)

        if pack[cls.MSGTYPE_ID - 2] != cls.MSGTYPE:
            raise ValueError('invalid message type')
        if pack[cls.VERSION_ID - 2] != cls.VERSION:
            raise ValueError('invalid protocol version')

        return FrameHeader(0, 0, pack[1], *pack[3:])

    def docnum(self):
        return struct.unpack('>I', b'\0' + self._docnum)[0]

    def recalculate_crc(self, body):
        f = crcmod.predefined.mkPredefinedCrcFun('crc-ccitt-false')
        pack = self.pack()
        self.crc = f(pack[:2] + pack[4:] + body)

    def __str__(self):
        return 'Заголовок Контейнера\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}\n' \
               '{:26}: {}'.format(
                    'Длина', self.length,
                    'Проверочный код', self.crc,
                    'Тип сообщения протокола', self.MSGTYPE,
                    'Тип фискального документа', self.doctype,
                    'Версия протокола', self.version,
                    'Служебные данные 1', self.extra1,
                    'Номер ФН', self.devnum,
                    'Номер ФД', self.docnum(),
                    'Служебные данные 2', self.extra2)


DOCUMENTS = {
    1: STLV(u'fiscalReport', u'Отчёт о фискализации', maxlen=658),
    11: STLV(u'fiscalReportCorrection', u'Отчёт об изменении параметров регистрации', maxlen=658),
    2: STLV(u'openShift', u'Отчёт об открытии смены', maxlen=440),
    21: STLV(u'currentStateReport', u'Отчёт о текущем состоянии расчетов', maxlen=32768),
    3: STLV(u'receipt', u'Кассовый чек', maxlen=32768),
    31: STLV(u'receiptCorrection', u'Кассовый чек коррекции', maxlen=32768),
    4: STLV(u'bso', u'Бланк строгой отчетности', maxlen=32768),
    41: STLV(u'bsoCorrection', u'Бланк строгой отчетности коррекции', maxlen=32768),
    5: STLV(u'closeShift', u'Отчёт о закрытии смены', maxlen=441),
    6: STLV(u'closeArchive', u'Отчёт о закрытии фискального накопителя', maxlen=432),
    7: STLV(u'operatorAck(?)', u'подтверждение оператора', maxlen=512),
    1001: Byte(u'autoMode', u'автоматический режим'),
    1002: Byte(u'offlineMode', u'автономный режим'),
    1003: String(u'<unknown-1003>', u'адрес банковского агента', maxlen=256),
    1004: String(u'<unknown-1004>', u'адрес банковского субагента', maxlen=256),
    1005: String(u'operatorAddress', u'адрес оператора по переводу денежных средств', maxlen=256),
    1006: String(u'<unknown-1006>', u'адрес платежного агента', maxlen=256),
    1007: String(u'<unknown-1007>', u'адрес платежного субагента', maxlen=256),
    1008: String(u'buyerAddress', u'адрес покупателя', maxlen=64),
    1009: String(u'retailPlaceAddress', u'адрес (место) расчетов', maxlen=256),
    1010: VLN(u'bankAgentRemuneration', u'Размер вознаграждения банковского агента (субагента)'),
    1011: VLN(u'paymentAgentRemuneration', u'Размер вознаграждения платежного агента (субагента)'),
    1012: UnixTime(u'dateTime', u'дата, время'),
    1013: String(u'kktNumber', u'Заводской номер ККТ', maxlen=20),
    1014: String(u'<unknown-1014>', u'значение типа строка', maxlen=64),
    1015: U32(u'<unknown-1015>', u'значение типа целое'),
    1016: String(u'operatorInn', u'ИНН оператора по переводу денежных средств', maxlen=12),
    1017: String(u'ofdInn', u'ИНН ОФД', maxlen=12),
    1018: String(u'userInn', u'ИНН пользователя', maxlen=12),
    1019: String(u'<unknown-1019>', u'Информационное cообщение', maxlen=64),
    1020: VLN(u'totalSum', u'ИТОГ'),
    1021: String(u'operator', u'Кассир', maxlen=64),
    1022: Byte(u'<unknown-1022>', u'код ответа ОФД'),
    1023: FVLN(u'quantity', u'Количество', maxlen=8),
    1024: String(u'<unknown-1024>', u'Наименование банковского агента', maxlen=64),
    1025: String(u'<unknown-1025>', u'Наименование банковского субагента', maxlen=64),
    1026: String(u'operatorName', u'Наименование оператора по переводу денежных средств', 64),
    1027: String(u'<unknown-1027>', u'Наименование платежного агента', maxlen=64),
    1028: String(u'<unknown-1028>', u'Наименование платежного субагента', maxlen=64),
    1029: String(u'<unknown-1029>', u'наименование реквизита', maxlen=64),
    1030: String(u'name', u'Наименование товара', maxlen=64),
    1031: VLN(u'cashTotalSum', u'Наличными'),
    1032: STLV(u'<unknown-1032>', u'Налог', maxlen=33),
    1033: STLV(u'<unknown-1033>', u'Налоги', maxlen=33),
    1034: FVLN(u'markup', u'Наценка (ставка)', maxlen=8),
    1035: VLN(u'markupSum', u'Наценка (сумма)'),
    1036: String(u'machineNumber', u'Номер автомата', maxlen=12),
    1037: String(u'kktRegId', u'Номер ККТ', maxlen=20),
    1038: U32(u'shiftNumber', u'Номер смены'),
    1039: String(u'<unknown-1039>', u'Зарезервирован', maxlen=12),
    1040: U32(u'fiscalDocumentNumber', u'номер фискального документа'),
    1041: String(u'fiscalDriveNumber', desc=u'заводской номер фискального накопителя', maxlen=16),
    1042: U32(u'requestNumber', u'номер чека за смену'),
    1043: VLN(u'sum', u'Общая стоимость позиции с учетом скидок и наценок'),
    1044: String(u'bankAgentOperation', u'Операция банковского агента', maxlen=24),
    1045: String(u'bankSubagentOperation', u'операция банковского субагента', maxlen=24),
    1046: String(u'<unknown-1046>', u'ОФД', maxlen=64),
    1047: STLV(u'<unknown-1047>', u'параметр настройки', maxlen=144),
    1048: String(u'user', u'наименование пользователя', maxlen=256),
    1049: String(u'<unknown-1049>', u'Почтовый индекс', maxlen=6),
    1050: Byte(u'fiscalDriveExhaustionSign', u'Признак исчерпания ресурса ФН'),
    1051: Byte(u'fiscalDriveReplaceRequiredSign', u'Признак необходимости срочной замены ФН'),
    1052: Byte(u'fiscalDriveMemoryExceededSign', u'Признак переполнения памяти ФН'),
    1053: Byte(u'ofdResponseTimeoutSign', u'Признак превышения времени ожидания ответа ОФД'),
    1054: Byte(u'operationType', u'Признак расчета'),
    1055: Byte(u'taxationType', u'применяемая система налогообложения'),
    1056: Byte(u'encryptionSign', u'Признак шифрования'),
    1057: Byte(u'<unknown-1057>', u'Применение платежными агентами (субагентами)'),
    1058: Byte(u'<unknown-1058>', u'Применение банковскими агентами (субагентами)'),
    1059: STLV(u'items', u'наименование товара (реквизиты)', 328, '*'),
    1060: String(u'<unknown-1060>', u'Сайт налогового органа', maxlen=64),
    1061: String(u'<unknown-1061>', u'Сайт ОФД', maxlen=64),
    1062: Byte(u'taxationType-2', u'системы налогообложения'),  # TODO: Bitfields actually, read more. Also dup with 1055.
    1063: FVLN(u'discount', u'Скидка (ставка)', 8),
    1064: VLN(u'discountSum', u'Скидка (сумма)'),
    1065: String(u'<unknown-1065>', u'Сокращенное наименование налога', maxlen=10),
    1066: String(u'message', u'Сообщение', maxlen=256),
    1067: STLV(u'<unknown-1067>', u'Сообщение оператора для ККТ', maxlen=216),
    1068: STLV(u'<unknown-1068>', u'сообщение оператора для ФН', maxlen=169),
    1069: STLV(u'message', u'Сообщение оператору', 328, '*'),
    1070: FVLN(u'<unknown-1070>', u'Ставка налога', maxlen=5),
    1071: STLV(u'stornoItems', u'сторно товара (реквизиты)', 328, '*'),
    1072: VLN(u'<unknown-1072>', u'Сумма налога', maxlen=8),
    1073: String(u'bankAgentPhone', u'Телефон банковского агента', maxlen=19),
    1074: String(u'paymentAgentPhone', u'Телефон платежного агента', maxlen=19),
    1075: String(u'operatorPhone', u'Телефон оператора по переводу денежных средств', maxlen=19),
    1076: String(u'type', u'Тип сообщения', maxlen=64),
    1077: VLN(u'fiscalSign', u'фискальный признак документа', maxlen=6),
    1078: ByteArray(u'<unknown-1078>', u'фискальный признак оператора', maxlen=8),
    1079: VLN(u'price', u'Цена за единицу'),
    1080: String(u'barcode', u'Штриховой код EAN13', maxlen=16),
    1081: VLN(u'ecashTotalSum', u'форма расчета – электронными'),
    1082: String(u'bankSubagentPhone', u'телефон банковского субагента', maxlen=19),
    1083: String(u'paymentSubagentPhone', u'телефон платежного субагента', maxlen=19),
    1084: STLV(u'properties', u'дополнительный реквизит', 328, '*'),
    1085: String(u'key', u'наименование дополнительного реквизита', maxlen=64),
    1086: String(u'value', u'значение дополнительного реквизита', maxlen=256),
    # 1087: u'Итог смены',
    # 1088:
    # 1089:
    # 1090:
    # 1091:
    # 1092:
    # 1093:
    # 1094:
    # 1095:
    # 1096:
    1097: U32(u'notTransmittedDocumentsQuantity', u'количество непереданных документов ФД'),
    1098: UnixTime(u'notTransmittedDocumentsDateTime', u'дата и время первого из непереданных ФД'),
    # 1099:
    # 1100:
    # 1101:
    1102: VLN(u'nds18', u'НДС итога чека со ставкой 18%'),
    1103: VLN(u'nds10', u'НДС итога чека со ставкой 10%'),
    1104: VLN(u'nds0', u'НДС итога чека со ставкой 0%'),
    1105: VLN(u'ndsNo', u'НДС не облагается'),
    1106: VLN(u'ndsCalculated18', u'НДС итога чека с рассчитанной ставкой 18%'),
    1107: VLN(u'ndsCalculated10', u'НДС итога чека с рассчитанной ставкой 10%'),
    1108: Byte(u'internetSign', u'признак расчетов в сети Интернет'),
    1109: Byte(u'serviceSign', u'признак работы в сфере услуг'),
    1110: Byte(u'bsoSign', u'применяется для формирования БСО'),  # TODO: Not sure about type.
    1111: U32(u'documentsQuantity', u'количество фискальных документов за смену'),  # TODO: Duplicate names with 1118.
    1112: STLV(u'modifiers', u'скидка/наценка', 160, '*'),
    1113: String(u'discountName', u'наименование скидки', 64),
    1114: String(u'markupName', u'наименование наценки', 64),
    1115: String(u'addressToCheckFiscalSign', u'адрес сайта для проверки ФП', 256),
    1116: U32(u'notTransmittedDocumentNumber', u'номер первого непереданного документа'),
    1117: String(u'senderAddress', u'адрес отправителя', 64),
    1118: U32(u'receiptsQuantity', u'количество кассовых чеков за смену'),  # TODO: Имя придумал сам, конфликт с 1111.
    1119: String(u'operatorPhoneToReceive', u'телефон оператора по приему платежей', 19),
}

SCHEMA = {
    '$schema': 'http://json-schema.org/draft-04/schema#',

    'common': {
        'items': {
            'type': 'object',
            'properties': {
                'name': {'$ref': '#/definitions/name'},
                'barcode': {'$ref': '#/definitions/barcode'},
                'price': {'$ref': '#/definitions/price'},
                'quantity': {'$ref': '#/definitions/quantity'},
                'modifiers': {'$ref': '#/definitions/modifiers'},
                'nds18': {'$ref': '#/definitions/nds18'},
                'nds10': {'$ref': '#/definitions/nds10'},
                'nds0': {'$ref': '#/definitions/nds0'},
                'ndsNo': {'$ref': '#/definitions/ndsNo'},
                'ndsCalculated18': {'$ref': '#/definitions/ndsCalculated18'},
                'ndsCalculated10': {'$ref': '#/definitions/ndsCalculated10'},
                'sum': {'$ref': '#/definitions/sum'},
                'properties': {'$ref': '#/definitions/properties'},
            },
            'additionalProperties': False,
            'required': ['name', 'quantity', 'sum'],
        },
    },

    'definitions': {
        'autoMode': {
            'tag': 1001,
            'type': 'number',
            'description': 'автоматический режим',
            'minimum': 0,
            'maximum': 1,
        },
        'offlineMode': {
            'tag': 1002,
            'type': 'number',
            'description': 'автономный режим',
            'minimum': 0,
            'maximum': 1,
        },
        'operatorAddress': {
            'tag': 1005,
            'type': 'string',
            'description': 'адрес оператора по переводу денежных средств',
            'maxLength': 256,
        },
        'buyerAddress': {
            'tag': 1008,
            'type': 'string',
            'description': 'адрес покупателя',
            'maxLength': 64,
        },
        'retailPlaceAddress': {
            'tag': 1009,
            'type': 'string',
            'description': 'адрес (место) расчетов',
            'maxLength': 256,
        },
        'bankAgentRemuneration': {
            'tag': 1010,
            'type': 'number',
            'description': 'размер вознаграждения банковского агента (субагента)',
        },
        'paymentAgentRemuneration': {
            'tag': 1011,
            'type': 'number',
            'description': 'размер вознаграждения платежного агента (субагента)',
        },
        'dateTime': {
            'tag': 1012,
            'type': 'number',
            'description': 'дата, время',
        },
        'operatorInn': {
            'tag': 1016,
            'type': 'string',
            'description': 'ИНН оператора по переводу денежных средств',
            'minLength': 12,
            'maxLength': 12,
        },
        'userInn': {
            'tag': 1018,
            'type': 'string',
            'description': 'ИНН пользователя',
            'minLength': 12,
            'maxLength': 12,
        },
        'totalSum': {
            'tag': 1020,
            'type': 'number',
            'description': 'ИТОГ',
        },
        'operator': {
            'tag': 1021,
            'type': 'string',
            'description': 'кассир',
            'maxLength': 64,
        },
        'quantity': {
            'tag': 1023,
            'type': 'number',
            'description': 'количество',
        },
        'operatorName': {
            'tag': 1026,
            'type': 'string',
            'description': 'наименование оператора по переводу денежных средств',
            'maxLength': 64,
        },
        'name': {
            'tag': 1030,
            'type': 'string',
            'description': 'наименование товара',
            'maxLength': 64,
        },
        'cashTotalSum': {
            'tag': 1031,
            'type': 'number',
            'description': 'форма расчета - наличными',
        },
        'markup': {
            'tag': 1034,
            'type': 'number',
            'description': 'наценка (ставка)',
        },
        'markupSum': {
            'tag': 1035,
            'type': 'number',
            'description': 'наценка (сумма)',
        },
        'kktRegId': {
            'tag': 1037,
            'type': 'string',
            'description': 'регистрационный номер ККТ',
            'minLength': 20,
            'maxLength': 20,
        },
        'shiftNumber': {
            'tag': 1038,
            'type': 'number',
            'description': 'номер смены',
        },
        'fiscalDocumentNumber': {
            'tag': 1040,
            'type': 'number',
            'description': 'порядковый номер фискального документа',
        },
        'fiscalDriveNumber': {
            'tag': 1041,
            'type': 'string',
            'description': 'заводской номер фискального накопителя',
            'minLength': 16,
            'maxLength': 16,
        },
        'requestNumber': {
            'tag': 1042,
            'type': 'number',
            'description': 'номер чека за смену',
        },
        'sum': {
            'tag': 1043,
            'type': 'number',
            'description': 'общая стоимость позиции с учетом скидок и наценок',
        },
        'bankAgentOperation': {
            'tag': 1044,
            'type': 'string',
            'description': 'операция банковского агента',
            'maxLength': 24,
        },
        'bankSubagentOperation': {
            'tag': 1045,
            'type': 'string',
            'description': 'операция банковского субагента',
            'maxLength': 24,
        },
        'user': {
            'tag': 1048,
            'type': 'string',
            'description': 'наименование пользователя',
            'maxLength': 256,
        },
        'fiscalDriveExhaustionSign': {
            'tag': 1050,
            'type': 'number',
            'description': 'признак исчерпания ресурса ФН',
            'minimum': 0,
            'maximum': 1,
        },
        'fiscalDriveReplaceRequiredSign': {
            'tag': 1051,
            'type': 'number',
            'description': 'признак необходимости срочной замены ФН',
            'minimum': 0,
            'maximum': 1,
        },
        'fiscalDriveMemoryExceededSign': {
            'tag': 1052,
            'type': 'number',
            'description': 'признак переполнения памяти ФН',
            'minimum': 0,
            'maximum': 1,
        },
        'ofdResponseTimeoutSign': {
            'tag': 1053,
            'type': 'number',
            'description': 'признак превышения времени ожидания ответа ОФД',
            'minimum': 0,
            'maximum': 1,
        },
        'operationType': {
            'tag': 1054,
            'type': 'number',
            'minimum': 1,
            'maximum': 4,
            'description': 'признак расчета',
        },
        # TODO: В налоговом документе это поле имеет тэг 1062.
        'taxationType': {
            'tag': 1055,
            'type': 'number',
            'minimum': 0,
            'maximum': 255,
            'description': 'применяемая система налогообложения',
        },
        'items': {
            'tag': 1059,
            'type': 'array',
            'description': 'наименование товара (реквизиты)',
            'items': [
                {'$ref': '#/common/items'},
            ],
        },
        'discount': {
            'tag': 1063,
            'type': 'number',
            'description': 'скидка (ставка)',
        },
        'discountSum': {
            'tag': 1064,
            'type': 'number',
            'description': 'скидка (сумма)',
        },
        'message': {
            'tag': 1069,
            'type': 'array',
            'description': 'сообщение оператору',
        },
        'stornoItems': {
            'tag': 1071,
            'type': 'array',
            'description': 'сторно товара (реквизиты)',
            'items': [
                {'$ref': '#/common/items'},
            ],
        },
        'bankAgentPhone': {
            'tag': 1073,
            'type': 'string',
            'description': 'телефон банковского агента',
            'maxLength': 19,
        },
        'paymentAgentPhone': {
            'tag': 1074,
            'type': 'string',
            'description': 'телефон платежного агента',
            'maxLength': 19,
        },
        'operatorPhone': {
            'tag': 1075,
            'type': 'string',
            'description': 'телефон оператора по переводу денежных средств',
            'maxLength': 19,
        },
        'fiscalSign': {
            'tag': 1077,
            'type': 'number',
            'description': 'фискальный признак документа',
        },
        'price': {
            'tag': 1079,
            'type': 'number',
            'description': 'цена за единицу',
        },
        'barcode': {
            'tag': 1080,
            'type': 'string',
            'description': 'штриховой код EAN13',
            'maxLength': 16,
        },
        'ecashTotalSum': {
            'tag': 1081,
            'type': 'number',
            'description': 'форма расчета - электронными',
        },
        'bankSubagentPhone': {
            'tag': 1082,
            'type': 'string',
            'description': 'телефон банковского субагента',
            'maxLength': 19,
        },
        'paymentSubagentPhone': {
            'tag': 1083,
            'type': 'string',
            'description': 'телефон платежного субагента',
            'maxLength': 19,
        },
        'properties': {
            'tag': 1084,
            'type': 'array',
            'description': 'дополнительный реквизит',
            'items': [
                {
                    'type': 'object',
                    'properties': {
                        'key': {'$ref': '#/definitions/key'},
                        'value': {'$ref': '#/definitions/value'},
                    },
                    'additionalProperties': False,
                },
            ],
        },
        'key': {
            'tag': 1085,
            'type': 'string',
            'description': 'наименование дополнительного реквизита',
            'maxLength': 64,
        },
        'value': {
            'tag': 1086,
            'type': 'string',
            'description': 'значение дополнительного реквизита',
            'maxLength': 256,
        },
        'notTransmittedDocumentsQuantity': {
            'tag': 1097,
            'type': 'number',
            'description': 'кол-во неподтвержденных документов ФД',
        },
        'notTransmittedDocumentsDateTime': {
            'tag': 1098,
            'type': 'number',
            'description': 'дата и время первого из непереданных ФД',
        },
        'nds18': {
            'tag': 1102,
            'type': 'number',
            'description': 'НДС итога чека со ставкой 18%',
        },
        'nds10': {
            'tag': 1103,
            'type': 'number',
            'description': 'НДС итога чека со ставкой 10%',
        },
        'nds0': {
            'tag': 1104,
            'type': 'number',
            'description': 'НДС итога чека со ставкой 0%',
        },
        'ndsNo': {
            'tag': 1105,
            'type': 'number',
            'description': 'НДС не облагается',
        },
        'ndsCalculated18': {
            'tag': 1106,
            'type': 'number',
            'description': 'НДС итога чека с рассчитанной ставкой 18%',
        },
        'ndsCalculated10': {
            'tag': 1107,
            'type': 'number',
            'description': 'НДС итога чека с рассчитанной ставкой 10%',
        },
        'documentsQuantity': {
            'tag': 1111,
            'type': 'number',
            'description': 'количество фискальных документов за смену',
        },
        'modifiers': {
            'tag': 1112,
            'type': 'array',
            'description': 'скидка/наценка',
            'items': [
                {
                    'type': 'object',
                    'properties': {
                        'discountName': {'$ref': '#/definitions/discountName'},
                        'markupName': {'$ref': '#/definitions/markupName'},
                        'discount': {'$ref': '#/definitions/discount'},
                        'markup': {'$ref': '#/definitions/markup'},
                        'discountSum': {'$ref': '#/definitions/discountSum'},
                        'markupSum': {'$ref': '#/definitions/markupSum'},
                    },
                    'additionalProperties': False,
                },
            ],
        },
        'discountName': {
            'tag': 1113,
            'type': 'string',
            'description': 'наименование скидки',
            'maxLength': 64,
        },
        'markupName': {
            'tag': 1114,
            'type': 'string',
            'description': 'наименование наценки',
            'maxLength': 64,
        },
        'addressToCheckFiscalSign': {
            'tag': 1115,
            'type': 'string',
            'description': 'адрес сайта для проверки ФП',
            'maxLength': 256,
        },
        'senderAddress': {
            'tag': 1117,
            'type': 'string',
            'description': 'адрес отправителя',
            'maxLength': 64,
        },
        # TODO: Название сам придумал, в документе дубликат - documentsQuantity.
        'receiptsQuantity': {
            'tag': 1118,
            'type': 'number',
            'description': 'количество кассовых чеков за смену',
        },
        'operatorPhoneToReceive': {
            'tag': 1119,
            'type': 'string',
            'description': 'телефон оператора по приему платежей',
            'maxLength': 64,
        },
    },

    'receipt-bso': {
        'properties': {
            'user': {'$ref': '#/definitions/user'},
            'userInn': {'$ref': '#/definitions/userInn'},
            'requestNumber': {'$ref': '#/definitions/requestNumber'},
            'dateTime': {'$ref': '#/definitions/dateTime'},
            'shiftNumber': {'$ref': '#/definitions/shiftNumber'},
            'operationType': {'$ref': '#/definitions/operationType'},
            'taxationType': {'$ref': '#/definitions/taxationType'},
            'operator': {'$ref': '#/definitions/operator'},
            'kktRegId': {'$ref': '#/definitions/kktRegId'},
            'fiscalDriveNumber': {'$ref': '#/definitions/fiscalDriveNumber'},
            'retailPlaceAddress': {'$ref': '#/definitions/retailPlaceAddress'},
            'buyerAddress': {'$ref': '#/definitions/buyerAddress'},
            'senderAddress': {'$ref': '#/definitions/senderAddress'},
            'addressToCheckFiscalSign': {'$ref': '#/definitions/addressToCheckFiscalSign'},
            'items': {'$ref': '#/definitions/items'},
            'stornoItems': {'$ref': '#/definitions/stornoItems'},
            'paymentAgentRemuneration': {'$ref': '#/definitions/paymentAgentRemuneration'},
            'paymentAgentPhone': {'$ref': '#/definitions/paymentAgentPhone'},
            'paymentSubagentPhone': {'$ref': '#/definitions/paymentSubagentPhone'},
            'operatorPhoneToReceive': {'$ref': '#/definitions/operatorPhoneToReceive'},
            'operatorPhone': {'$ref': '#/definitions/operatorPhone'},
            'bankAgentPhone': {'$ref': '#/definitions/bankAgentPhone'},
            'bankSubagentPhone': {'$ref': '#/definitions/bankSubagentPhone'},
            'bankAgentOperation': {'$ref': '#/definitions/bankAgentOperation'},
            'bankSubagentOperation': {'$ref': '#/definitions/bankSubagentOperation'},
            'bankAgentRemuneration': {'$ref': '#/definitions/bankAgentRemuneration'},
            'operatorName': {'$ref': '#/definitions/operatorName'},
            'operatorAddress': {'$ref': '#/definitions/operatorAddress'},
            'operatorInn': {'$ref': '#/definitions/operatorInn'},
            'modifiers': {'$ref': '#/definitions/modifiers'},
            'nds18': {'$ref': '#/definitions/nds18'},
            'nds10': {'$ref': '#/definitions/nds10'},
            'nds0': {'$ref': '#/definitions/nds0'},
            'ndsNo': {'$ref': '#/definitions/ndsNo'},
            'ndsCalculated18': {'$ref': '#/definitions/ndsCalculated18'},
            'ndsCalculated10': {'$ref': '#/definitions/ndsCalculated10'},
            'totalSum': {'$ref': '#/definitions/totalSum'},
            'cashTotalSum': {'$ref': '#/definitions/cashTotalSum'},
            'ecashTotalSum': {'$ref': '#/definitions/ecashTotalSum'},
            'fiscalDocumentNumber': {'$ref': '#/definitions/fiscalDocumentNumber'},
            'fiscalSign': {'$ref': '#/definitions/fiscalSign'},
            'properties': {'$ref': '#/definitions/properties'},
        },
        'required': [
            'user',
            'userInn',
            'requestNumber',
            'dateTime',
            'shiftNumber',
            'operationType',
            'taxationType',
            'operator',
            'kktRegId',
            'fiscalDriveNumber',
            'totalSum',
            'cashTotalSum',
            'ecashTotalSum',
            'fiscalDocumentNumber',
            'fiscalSign',
        ],
    },

    'properties': {
        # TODO: Incomplete.
        'fiscalReport': {
            'type': 'object',
            'description': 'Отчет о регистрации',
            'tag': 1,
            'properties': {
                'autoMode': {'$ref': '#/definitions/autoMode'},
                'offlineMode': {'$ref': '#/definitions/offlineMode'},
                'user': {'$ref': '#/definitions/user'},
            },
            'required': [
                'user',
                'autoMode',
                'offlineMode'
            ],
        },
        'openShift': {
            'tag': 2,
            'type': 'object',
            'description': 'Отчет об открытии смены',
            'properties': {
                'user': {'$ref': '#/definitions/user'},
                'userInn': {'$ref': '#/definitions/userInn'},
                'operator': {'$ref': '#/definitions/operator'},
                'retailPlaceAddress': {'$ref': '#/definitions/retailPlaceAddress'},
                'dateTime': {'$ref': '#/definitions/dateTime'},
                'shiftNumber': {'$ref': '#/definitions/shiftNumber'},
                'kktRegId': {'$ref': '#/definitions/kktRegId'},
                'fiscalDriveNumber': {'$ref': '#/definitions/fiscalDriveNumber'},
                'fiscalDocumentNumber': {'$ref': '#/definitions/fiscalDocumentNumber'},
                'fiscalSign': {'$ref': '#/definitions/fiscalSign'},
                'message': {'$ref': '#/definitions/message'},
                'properties': {'$ref': '#/definitions/properties'},
            },
            'additionalProperties': False,
            'required': [
                'user',
                'userInn',
                'operator',
                'retailPlaceAddress',
                'dateTime',
                'shiftNumber',
                'kktRegId',
                'fiscalDriveNumber',
                'fiscalDocumentNumber',
                'fiscalSign'
            ],
        },
        'receipt': {
            'tag': 3,
            'type': 'object',
            'description': 'Кассовый чек',
            'properties': {
                'user': {'$ref': '#/definitions/user'},
                'userInn': {'$ref': '#/definitions/userInn'},
                'requestNumber': {'$ref': '#/definitions/requestNumber'},
                'dateTime': {'$ref': '#/definitions/dateTime'},
                'shiftNumber': {'$ref': '#/definitions/shiftNumber'},
                'operationType': {'$ref': '#/definitions/operationType'},
                'taxationType': {'$ref': '#/definitions/taxationType'},
                'operator': {'$ref': '#/definitions/operator'},
                'kktRegId': {'$ref': '#/definitions/kktRegId'},
                'fiscalDriveNumber': {'$ref': '#/definitions/fiscalDriveNumber'},
                'retailPlaceAddress': {'$ref': '#/definitions/retailPlaceAddress'},
                'buyerAddress': {'$ref': '#/definitions/buyerAddress'},
                'senderAddress': {'$ref': '#/definitions/senderAddress'},
                'addressToCheckFiscalSign': {'$ref': '#/definitions/addressToCheckFiscalSign'},
                'items': {'$ref': '#/definitions/items'},
                'stornoItems': {'$ref': '#/definitions/stornoItems'},
                'paymentAgentRemuneration': {'$ref': '#/definitions/paymentAgentRemuneration'},
                'paymentAgentPhone': {'$ref': '#/definitions/paymentAgentPhone'},
                'paymentSubagentPhone': {'$ref': '#/definitions/paymentSubagentPhone'},
                'operatorPhoneToReceive': {'$ref': '#/definitions/operatorPhoneToReceive'},
                'operatorPhone': {'$ref': '#/definitions/operatorPhone'},
                'bankAgentPhone': {'$ref': '#/definitions/bankAgentPhone'},
                'bankSubagentPhone': {'$ref': '#/definitions/bankSubagentPhone'},
                'bankAgentOperation': {'$ref': '#/definitions/bankAgentOperation'},
                'bankSubagentOperation': {'$ref': '#/definitions/bankSubagentOperation'},
                'bankAgentRemuneration': {'$ref': '#/definitions/bankAgentRemuneration'},
                'operatorName': {'$ref': '#/definitions/operatorName'},
                'operatorAddress': {'$ref': '#/definitions/operatorAddress'},
                'operatorInn': {'$ref': '#/definitions/operatorInn'},
                'modifiers': {'$ref': '#/definitions/modifiers'},
                'nds18': {'$ref': '#/definitions/nds18'},
                'nds10': {'$ref': '#/definitions/nds10'},
                'nds0': {'$ref': '#/definitions/nds0'},
                'ndsNo': {'$ref': '#/definitions/ndsNo'},
                'ndsCalculated18': {'$ref': '#/definitions/ndsCalculated18'},
                'ndsCalculated10': {'$ref': '#/definitions/ndsCalculated10'},
                'totalSum': {'$ref': '#/definitions/totalSum'},
                'cashTotalSum': {'$ref': '#/definitions/cashTotalSum'},
                'ecashTotalSum': {'$ref': '#/definitions/ecashTotalSum'},
                'fiscalDocumentNumber': {'$ref': '#/definitions/fiscalDocumentNumber'},
                'fiscalSign': {'$ref': '#/definitions/fiscalSign'},
                'properties': {'$ref': '#/definitions/properties'},
            },
            'additionalProperties': False,
            'required': [
                'user',
                'userInn',
                'requestNumber',
                'dateTime',
                'shiftNumber',
                'operationType',
                'taxationType',
                'operator',
                'kktRegId',
                'fiscalDriveNumber',
                'totalSum',
                'cashTotalSum',
                'ecashTotalSum',
                'fiscalDocumentNumber',
                'fiscalSign',
            ],
        },
        # 'bso': {
        #     'tag': 4,
        #     'type': 'object',
        #     'description': 'БСО',
        #     '$properties': '#/properties/receipt/properties',
        #     'additionalProperties': False,
        #     '$required': '#/properties/receipt/required',
        # },
        'closeShift': {
            'tag': 5,
            'type': 'object',
            'description': 'Отчёт о закрытии смены',
            'properties': {
                'user': {'$ref': '#/definitions/user'},
                'userInn': {'$ref': '#/definitions/userInn'},
                'operator': {'$ref': '#/definitions/operator'},
                'dateTime': {'$ref': '#/definitions/dateTime'},
                'shiftNumber': {'$ref': '#/definitions/shiftNumber'},
                'receiptsQuantity': {'$ref': '#/definitions/receiptsQuantity'},
                'documentsQuantity': {'$ref': '#/definitions/documentsQuantity'},
                'notTransmittedDocumentsQuantity': {'$ref': '#/definitions/notTransmittedDocumentsQuantity'},
                'notTransmittedDocumentsDateTime': {'$ref': '#/definitions/notTransmittedDocumentsDateTime'},
                'ofdResponseTimeoutSign': {'$ref': '#/definitions/ofdResponseTimeoutSign'},
                'fiscalDriveReplaceRequiredSign': {'$ref': '#/definitions/fiscalDriveReplaceRequiredSign'},
                'fiscalDriveMemoryExceededSign': {'$ref': '#/definitions/fiscalDriveMemoryExceededSign'},
                'fiscalDriveExhaustionSign': {'$ref': '#/definitions/fiscalDriveExhaustionSign'},
                'kktRegId': {'$ref': '#/definitions/kktRegId'},
                'fiscalDriveNumber': {'$ref': '#/definitions/fiscalDriveNumber'},
                'fiscalDocumentNumber': {'$ref': '#/definitions/fiscalDocumentNumber'},
                'fiscalSign': {'$ref': '#/definitions/fiscalSign'},
                'message': {'$ref': '#/definitions/message'},
                'properties': {'$ref': '#/definitions/properties'},
            },
            'additionalProperties': False,
            'required': [
                'user',
                'userInn',
                'operator',
                'dateTime',
                'shiftNumber',
                'receiptsQuantity',
                'documentsQuantity',
                'notTransmittedDocumentsQuantity',
                'notTransmittedDocumentsDateTime',
                'ofdResponseTimeoutSign',
                'fiscalDriveReplaceRequiredSign',
                'fiscalDriveMemoryExceededSign',
                'fiscalDriveExhaustionSign',
                'kktRegId',
                'fiscalDriveNumber',
                'fiscalDocumentNumber',
                'fiscalSign',
            ],
        },
    },

    'additionalProperties': False,
    'oneOf': [
        {'required': ['fiscalReport']},
        {'required': ['openShift']},
        {'required': ['receipt']},
        # {'required': ['bso']},
        {'required': ['closeShift']},
    ],
}

DOCS_BY_NAME = dict((doc.name, (ty, doc)) for ty, doc in DOCUMENTS.items())
DOCS_BY_DESC = dict((doc.desc, (ty, doc)) for ty, doc in DOCUMENTS.items())


def pack_json(doc, docs=DOCS_BY_DESC):
    """
    Packs the given JSON document into a bytearray using optionally specified documents container.

    :param doc: valid JSON document as object.
    :param docs: documents container.
    :return: packed document representation as a bytearray.
    """
    wr = b''
    for name, value in doc.items():
        ty, cls = docs[name]
        if isinstance(value, dict):
            data = pack_json(value)
        elif isinstance(value, list):
            data = b''
            for item in value:
                data += pack_json(item)
        else:
            data = cls.pack(value)

        wr += struct.pack('<HH', ty, len(data))
        wr += data

    return wr
