# coding: utf8
#
#        Copyright (C) 2017 Yandex LLC
#        http://yandex.com
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#

import asyncio
import json
import time
import argparse
from ofd.protocol import SessionHeader, FrameHeader, unpack_container_message, pack_json, DOCS_BY_NAME, DocCodes, \
    String


async def unpack_incoming_message(rd):
    """
    Прочитать входящий поток бинарных данных и распаковать их в json документ
    """
    session_raw = await rd.readexactly(SessionHeader.STRUCT.size)
    session = SessionHeader.unpack_from(session_raw)
    print(session)
    container_raw = await rd.readexactly(session.length)
    header_raw, message_raw = container_raw[:FrameHeader.STRUCT.size], container_raw[FrameHeader.STRUCT.size:]
    header = FrameHeader.unpack_from(header_raw)
    print(header)
    return unpack_container_message(message_raw, b'0')[0], session, header


def create_response(doc, in_session, in_header):
    """
    Запаковать в протокол "подтверждение оператора" от ОФД к кассе
    :param doc: полученный документ
    :param in_header: заголовок контейнера входящего сообщения
    :param in_session: заголовок сессии входящего сообщения
    :return: 
    """
    doc_body = doc[next(iter(doc))]  # получаем тело документа
    message = {
        'operatorAck': {
            'ofdInn': '7704358518',  # ИНН Яндекс.ОФД
            'fiscalDriveNumber': doc_body.get('fiscalDriveNumber'),
            'fiscalDocumentNumber': doc_body.get('fiscalDocumentNumber'),
            'dateTime': int(time.time()),
            'messageToFn': {'ofdResponseCode': 0}  # код ответа 0 при успешном получении документа
            # Теги ФПО и ФПП не указаны, т.к. должны быть добавлены реальным шифровальным комплексом
        }
    }
    message_raw = pack_json(message, docs=DOCS_BY_NAME)

    # в реальных ОФД FrameHeader формируется автоматически шифровальной машиной
    out_header = FrameHeader(length=FrameHeader.STRUCT.size + len(message_raw),
                             crc=0,
                             doctype=DocCodes.OPERATOR_ACK,
                             devnum=in_header.devnum,
                             docnum=String.pack(str(doc_body.get('fiscalDocumentNumber'))),
                             extra1=in_header.extra1,
                             extra2=String.pack('0'.rjust(12)))

    out_header.recalculate_crc(message_raw)
    container_raw = out_header.pack() + message_raw

    out_session = SessionHeader(pva=in_session.pva, fs_id=in_session.fs_id, length=len(container_raw), crc=0,
                                flags=0b0000000000010100)

    return out_session.pack() + container_raw


async def handle_connection(rd, wr):
    """
    Пример использования протокола для эмуляции работы ОФД. Сервер принимает входящее сообщение и распаковывает его,
    выводя значения в stdout. В ответ сервер формирует сообщение "подтверждение оператора" и передает его обратно кассе.
    Эмулятор работает без использования шифровальный машины, поэтому считаем, что сообщение приходит в ОФД 
    в незашифрованном виде.
    :param rd: readable stream.
    :param wr: writable stream.
    """
    try:
        doc, session, header = await unpack_incoming_message(rd)
        print(json.dumps(doc, ensure_ascii=False, indent=4))
        response = create_response(doc, in_session=session, in_header=header)
        print('raw response', response)
        wr.write(response)
    finally:
        wr.write_eof()
        wr.drain()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default=None, help='хост для запуска сервера')
    parser.add_argument('--port', default=12345, type=int, help='порт для запуска сервера')
    argv = parser.parse_args()
    host = None if argv.host in ['::', 'localhost'] else argv.host

    loop = asyncio.get_event_loop()
    server = asyncio.start_server(handle_connection, host=host, port=argv.port, loop=loop)
    loop.run_until_complete(server)
    print('mock ofd server has been started at port', argv.port)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('received SIGINT, shutting down')

    server.close()

    loop.run_until_complete(server.wait_closed())
    loop.close()
