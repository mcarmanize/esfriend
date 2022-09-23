"""
    Utility methods

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

import hashlib
import subprocess
import platform


def sha256sum(file_path):
    sha256 = hashlib.sha256()
    block_size = 0x1000
    with open(file_path, "rb") as f:
        chunk = f.read(block_size)
        while chunk:
            sha256.update(chunk)
            chunk = f.read(block_size)

        checksum = sha256.hexdigest()
        return checksum


def ping(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    return (
        subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        == 0
    )
