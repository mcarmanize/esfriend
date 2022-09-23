"""
    This script saves all the request headers from a mitmdump file
    as long as they do not contain apple.com in the host

    esfriend - a minimal malware analysis sandbox framework for macOS
    Copyright (C) <2022> Matt Carman

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
"""

from mitmproxy.net.http.http1.assemble import assemble_request_head


class Decoder:
    def __init__(self):
        self.f = open("request_headers.txt", "wb")

    def response(self, flow):
        try:
            if "apple.com" not in flow.request.host:
                self.f.write(assemble_request_head(flow.request))

        except Exception as err:
            self.f.write(
                bytes("err==================================\n".encode("iso-8859-1"))
            )
            self.f.write(err)


addons = [
    Decoder(),
]
