"""
    Config file for ESFriend analysis machine

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

# to configure connection string with password use
# mongodb://username:password@server:port
# to configure connection string without password use
# mongodb://server:port
MONGO_CONNECTION_STRING = """mongodb://0.0.0.0:27017"""

# path to mitmdump
# installing the python mitmproxy module will override the /usr/local/bin/mitmdump path
# using the brew install path directly to avoid legacy bugs
MITMDUMP = "/usr/local/Cellar/mitmproxy/8.1.1/bin/mitmdump"


# add additional machines as new dicts within list
# avoid configuring port 8081 for mitm
# the web UI to fully analyze the mitmdump uses port 8081
MACHINES = {
    "macOS12-1": {
        "ipaddress": "192.168.1.198",
        "mitm_port": 8080,
    },
    # "macOS13-1": {
    #     "ipaddress": "192.168.1.199",
    #     "mitm_port": 8082
    # }
}
