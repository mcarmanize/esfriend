"""
    Config for the esfriend sandbox machine

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

MACHINE_NAME = "macOS12-1"
MACHINE_TYPE = "physical"

P7ZIP = "/opt/homebrew/bin/7z"
ESLOGGER = "/usr/bin/eslogger"
TCPDUMP = "/usr/sbin/tcpdump"

ESFRIEND_SERVER = "192.168.1.62"

# to configure connection string with password use
# mongodb://username:password@server:port
# to configure connection string without password use
# mongodb://server:port
MONGO_CONNECTION_STRING = """mongodb://192.168.1.63:27017"""
