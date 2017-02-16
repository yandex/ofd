# CODING: UTF8

import array
import ofd
import struct
import unittest


class TestU32(unittest.TestCase):
    def test_unpack(self):
        actual = ofd.U32(name='', desc='').unpack(b'\x01\x00\x00\x00')
        self.assertEqual(1, actual)


class TestVLN(unittest.TestCase):
    def test_unpack(self):
        actual = ofd.VLN(name='', desc='', maxlen=3).unpack(b'\xe9\x2d\x06')
        self.assertEqual(404969, actual)

    def test_pack_when_max_length_less_8_bytes(self):
        number = 87892227523633
        vln = ofd.VLN(name='fiscalSign', desc='фискальный признак', maxlen=6)

        packed = vln.pack(number)
        assert b'1\x04\x00\x01\xf0O' == packed
        assert number == vln.unpack(packed)

    def test_pack_when_number_greater_then_max(self):
        number = 87892227523633222
        vln = ofd.VLN(name='fiscalSign', desc='фискальный признак', maxlen=6)
        with self.assertRaises(ValueError):
            vln.pack(number)


class TestFVLN(unittest.TestCase):
    def test_unpack(self):
        actual = ofd.FVLN(name='', desc='', maxlen=5).unpack(b'\x02\x15\xcd\x5b\x07')
        self.assertAlmostEqual(1234567.89, actual, delta=1e-3)

    def test_pack_two_points(self):
        number = 1234567.89
        fvln = ofd.FVLN(name='', desc='', maxlen=5)
        packed = fvln.pack(number)
        assert b'\x02\x15\xcd\x5b\x07' == packed
        unpacked = fvln.unpack(packed)
        assert number == unpacked

    def test_pack_several_points(self):
        number = 1453.67
        fvln = ofd.FVLN(name='', desc='', maxlen=8)
        packed = fvln.pack(number)
        assert b'\x02\xd77\x02\x00\x00\x00\x00' == packed
        unpacked = fvln.unpack(packed)
        assert number == unpacked

    def test_pack_bigger_number_should_raise_error(self):
        number = 1234567123.893
        fvln = ofd.FVLN(name='', desc='', maxlen=5)
        with self.assertRaises(ValueError):
            fvln.pack(number)


class TestString(unittest.TestCase):
    def test_unpack_zero_string(self):
        data = b''
        self.assertEqual(b'', struct.unpack('{}s'.format(len(data)), data)[0])

    def test_unpack(self):
        actual = ofd.String(name='', desc='', maxlen=4).unpack(b'\x92\xa5\xe1\xe2')
        self.assertEqual(u'Тест', actual)


class TestUnix(unittest.TestCase):
    def test_unpack(self):
        actual = ofd.UnixTime(name='', desc='').unpack(b'\x8a\x02\x9e\x55')
        self.assertEqual(1436418698, actual)


class TestByte(unittest.TestCase):
    def test_unpack_byte(self):
        self.assertEqual(3, ofd.Byte(name='', desc='').unpack(b'\x03'))

    def test_pack_byte(self):
        self.assertEqual(b'\x03', ofd.Byte(name='', desc='').pack(3))

    def test_pack_byte_throws_on_length_mismatch(self):
        with self.assertRaises(Exception):
            ofd.Byte(name='', desc='').pack(256)

    def test_unpack_byte_throws_on_length_mismatch(self):
        with self.assertRaises(Exception):
            ofd.Byte(name='', desc='').unpack('\x03\x04')


class TestSessionHeader(unittest.TestCase):
    def test_unpack(self):
        expected = ofd.SessionHeader(256, b'9999078950      ', 305, 0b10100, crc=0)
        data = [
            0x2a, 0x08, 0x41, 0x0a, 0x81, 0xa2, 0x00, 0x01,
            0x39, 0x39, 0x39, 0x39, 0x30, 0x37, 0x38, 0x39,
            0x35, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x31, 0x01, 0x14, 0x00, 0x00, 0x00
        ]
        data = array.array('B', data).tobytes()

        actual = ofd.SessionHeader.unpack_from(data)

        self.assertEqual(expected.pva, actual.pva)
        self.assertEqual(expected.fs_id, actual.fs_id)
        self.assertEqual(expected.length, actual.length)
        self.assertEqual(expected.flags, actual.flags)
        self.assertEqual(expected.crc, actual.crc)

    def test_pack_unpack(self):
        data = [
            0x2a, 0x08, 0x41, 0x0a, 0x81, 0xa2, 0x00, 0x01,
            0x39, 0x39, 0x39, 0x39, 0x30, 0x37, 0x38, 0x39,
            0x35, 0x30, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0x31, 0x01, 0x14, 0x00, 0x00, 0x00
        ]
        data = array.array('B', data).tobytes()

        self.assertEqual(data, ofd.SessionHeader.unpack_from(data).pack())


class TestFrameHeader(unittest.TestCase):
    def test_unpack(self):
        expected = ofd.FrameHeader(
            length=305,
            crc=60419,
            doctype=1,
            devnum=b'\x99\x99\x07\x89\x124V\x7f',
            docnum=b'\x00\x00\x01',
            extra1=b'\x10\t',
            extra2=b'\x00#\t\x82\xc4\x00\x00\x01\x00\x02\x01\x07')
        data = [
            0x31, 0x01, 0x03, 0xec, 0xa5, 0x01, 0x01, 0x10,
            0x09, 0x99, 0x99, 0x07, 0x89, 0x12, 0x34, 0x56,
            0x7f, 0x00, 0x00, 0x01, 0x00, 0x23, 0x09, 0x82,
            0xc4, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x07
        ]
        data = array.array('B', data).tobytes()

        actual = ofd.FrameHeader.unpack_from(data)

        self.assertEqual(expected.length, actual.length)
        self.assertEqual(expected.crc, actual.crc)
        self.assertEqual(expected.msgtype, actual.msgtype)
        self.assertEqual(expected.doctype, actual.doctype)
        self.assertEqual(expected.version, actual.version)
        self.assertEqual(expected.devnum, actual.devnum)
        self.assertEqual(expected.docnum(), actual.docnum())
        self.assertEqual(expected.extra1, actual.extra1)
        self.assertEqual(expected.extra2, actual.extra2)

    def test_pack_unpack(self):
        data = [
            0x31, 0x01, 0x03, 0xec, 0xa5, 0x01, 0x01, 0x10,
            0x09, 0x99, 0x99, 0x07, 0x89, 0x12, 0x34, 0x56,
            0x7f, 0x00, 0x00, 0x01, 0x00, 0x23, 0x09, 0x82,
            0xc4, 0x00, 0x00, 0x01, 0x00, 0x02, 0x01, 0x07
        ]
        data = array.array('B', data).tobytes()

        self.assertEqual(data, ofd.FrameHeader.unpack_from(data).pack())

    def test_update_crc(self):
        head = ofd.FrameHeader(
            length=305,
            crc=0,
            doctype=1,
            devnum=b'\x99\x99\x07\x89\x124V\x7f',
            docnum=b'\x00\x00\x01',
            extra1=b'\x10\t',
            extra2=b'\x00#\t\x82\xc4\x00\x00\x01\x00\x02\x01\x07')

        body = [
            0x01, 0x00, 0x03, 0x01, 0x11, 0x04, 0x10, 0x00,
            0x39, 0x39, 0x39, 0x39, 0x30, 0x37, 0x38, 0x39,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x20,
            0x0d, 0x04, 0x14, 0x00, 0x31, 0x32, 0x30, 0x30,
            0x30, 0x30, 0x31, 0x33, 0x30, 0x30, 0x30, 0x30,
            0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
            0xfa, 0x03, 0x0c, 0x00, 0x31, 0x31, 0x32, 0x32,
            0x33, 0x33, 0x34, 0x34, 0x35, 0x35, 0x36, 0x36,
            0x10, 0x04, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00,
            0xf4, 0x03, 0x04, 0x00, 0x28, 0x54, 0x0e, 0x57,
            0x35, 0x04, 0x06, 0x00, 0x21, 0x04, 0x1c, 0x6b,
            0x81, 0xa4, 0xe9, 0x03, 0x01, 0x00, 0x00, 0xea,
            0x03, 0x01, 0x00, 0x00, 0x20, 0x04, 0x01, 0x00,
            0x00, 0x26, 0x04, 0x01, 0x00, 0x01, 0x18, 0x04,
            0x09, 0x00, 0x8e, 0x8e, 0x8e, 0x20, 0x22, 0x8c,
            0x8c, 0x8c, 0x22, 0x21, 0x04, 0x01, 0x00, 0x00,
            0x22, 0x04, 0x01, 0x00, 0x00, 0xf1, 0x03, 0x26,
            0x00, 0x8c, 0xae, 0xe1, 0xaa, 0xa2, 0xa0, 0x2c,
            0x20, 0x87, 0xa5, 0xab, 0xa5, 0xad, 0xeb, 0xa9,
            0x20, 0xaf, 0xe0, 0xae, 0xe1, 0xaf, 0xa5, 0xaa,
            0xe2, 0x2c, 0x20, 0xa4, 0x2e, 0x36, 0x36, 0x20,
            0xaa, 0xae, 0xe0, 0xaf, 0x2e, 0x20, 0x32, 0x16,
            0x04, 0x08, 0x00, 0x8e, 0x94, 0x84, 0x2d, 0xe2,
            0xa5, 0xe1, 0xe2, 0x25, 0x04, 0x0a, 0x00, 0x77,
            0x77, 0x77, 0x2e, 0x6f, 0x66, 0x64, 0x2e, 0x72,
            0x75, 0x24, 0x04, 0x0c, 0x00, 0x77, 0x77, 0x77,
            0x2e, 0x6e, 0x61, 0x6c, 0x6f, 0x67, 0x2e, 0x72,
            0x75, 0x19, 0x04, 0x06, 0x00, 0x31, 0x31, 0x31,
            0x32, 0x33, 0x34, 0xfd, 0x03, 0x12, 0x00, 0x91,
            0x88, 0x91, 0x2e, 0x20, 0x80, 0x84, 0x8c, 0x88,
            0x8d, 0x88, 0x91, 0x92, 0x90, 0x80, 0x92, 0x8e,
            0x90, 0xf5, 0x03, 0x0a, 0x00, 0x30, 0x36, 0x32,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x81,
            0x06, 0x73, 0xfc, 0xa3, 0x4b, 0x28, 0x72, 0x00,
            0x00
        ]
        data = array.array('B', body).tobytes()

        head.recalculate_crc(data)
        self.assertEqual(60419, head.crc)

    def test_pack_byte_from_json(self):
        doc = {
            'код ответа ОФД': 42,
        }

        self.assertEqual(struct.pack('<HHc', 1022, 1, ofd.Byte('', '').pack(42)), ofd.protocol.pack_json(doc))

    def test_pack_nested_array_from_json(self):
        doc = {
            'параметр настройки': [
                {
                    'значение типа целое': 42,
                }
            ]
        }

        wr0 = b''
        wr0 += struct.pack('<HH', 1015, 4)
        wr0 += ofd.U32('', '').pack(42)
        wr = b''
        wr += struct.pack('<HH', 1047, len(wr0))
        wr += wr0
        self.assertEqual(wr, ofd.protocol.pack_json(doc))

    def test_pack_nested_object_from_json(self):
        doc = {
            'подтверждение оператора': {
                'сообщение оператора для ФН': {
                    'параметр настройки': [
                        {
                            'значение типа целое': 42,
                        }
                    ]
                }
            }
        }

        wr0 = b''
        wr0 += struct.pack('<HH', 1015, 4)
        wr0 += ofd.U32('', '').pack(42)
        wr1 = b''
        wr1 += struct.pack('<HH', 1047, len(wr0))
        wr1 += wr0
        wr2 = b''
        wr2 += struct.pack('<HH', 1068, len(wr1))
        wr2 += wr1
        wr3 = b''
        wr3 += struct.pack('<HH', 7, len(wr2))
        wr3 += wr2
        self.assertEqual(wr3, ofd.protocol.pack_json(doc))

if __name__ == '__main__':
    unittest.main()
