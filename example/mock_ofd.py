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
from ofd.protocol import SessionHeader, FrameHeader, unpack_container_message

async def handle_connection(rd, wr):
    """
    Called each time new connection is accepted.
    :param rd: readable stream.
    :param wr: writable stream.
    """
    try:
        session_raw = await rd.readexactly(30)
        session = SessionHeader.unpack_from(session_raw)
        print(session)

        container_raw = await rd.readexactly(session.length)
        header_raw, message_raw = container_raw[:FrameHeader.STRUCT.size], container_raw[FrameHeader.STRUCT.size:]
        header = FrameHeader.unpack_from(header_raw)
        print(header)

        document = unpack_container_message(message_raw, b'0')[0]
        print(json.dumps(document, ensure_ascii=False, indent=4))
    finally:
        wr.write_eof()

if __name__ == '__main__':
    host = None
    port = 12345

    loop = asyncio.get_event_loop()
    server = asyncio.start_server(handle_connection, host=host, port=port, loop=loop)
    loop.run_until_complete(server)
    print('mock ofd server has been started at port', port)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        print('received SIGINT, shutting down')

    server.close()

    loop.run_until_complete(server.wait_closed())
    loop.close()
