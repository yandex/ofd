# coding: utf8

import array
import json
import os

import crcmod
import crcmod.predefined
import decimal
import struct

import jsonschema

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

DOCUMENT_CODES = {'receipt', 'receiptCorrection', 'bso', 'bsoCorrection'}

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
    1062: Byte(u'taxationType?', u'система налогообложения'),
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
    1075: String(u'operatorPhoneToTransfer', u'Телефон оператора по переводу денежных средств', maxlen=19),
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
    # 1120:
    # 1121:
    # 1122:
    # 1123:
    # 1124:
    # 1125:
    # 1126:
    # 1127:
}

DOCS_BY_NAME = dict((doc.name, (ty, doc)) for ty, doc in DOCUMENTS.items())
DOCS_BY_DESC = dict((doc.desc, (ty, doc)) for ty, doc in DOCUMENTS.items())


class NullValidator(object):
    def validate(self, doc: dict):
        pass


class DocumentValidator(object):
    def __init__(self, path):
        path = os.path.join(path, 'document.schema.json')
        with open(path, encoding='utf-8') as fh:
            self._root = json.loads(fh.read())
            self._resolver = jsonschema.RefResolver('file://' + path, None)

    def validate(self, doc: dict):
        jsonschema.validate(doc, self._root, resolver=self._resolver)


def pack_json(doc: dict, docs: dict=DOCS_BY_DESC) -> bytes:
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
