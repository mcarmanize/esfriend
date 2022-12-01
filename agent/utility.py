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
import os
from database import DatabaseConnection
from agent_config import MONGO_CONNECTION_STRING, P7ZIP


def sha256sum(file_path):
    """get file checksum from file path"""
    try:
        sha256 = hashlib.sha256()
        block_size = 0x1000
        with open(file_path, "rb") as f:
            chunk = f.read(block_size)
            while chunk:
                sha256.update(chunk)
                chunk = f.read(block_size)

            checksum = sha256.hexdigest()
            return checksum
    except Exception as err:
        return err


def p7z(file_path):
    """use p7zip to extract a file by file path"""
    command = [P7ZIP, "x", file_path, "-o/tmp"]
    p7z_process = subprocess.Popen(command, stdout=subprocess.PIPE)
    p7z_process.communicate()
    result = p7z_process.returncode == 0
    print("7z returncode: {}".format(p7z_process.returncode))
    print("7z result: {}".format(result))
    return result


def find_app_in_tmp():
    """walk tmp to find .app package"""
    for root, dirs, _ in os.walk("/tmp"):
        for directory in dirs:
            if "__MACOSX" in directory:
                pass
            else:
                if directory.endswith(".app"):
                    return os.path.join(root, directory)


def add_x_flag(file_path):
    """add execute flag to file"""
    chmod_cmd = ["/bin/chmod", "+x", file_path]
    result = (
        subprocess.call(chmod_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        == 0
    )
    return result

def get_process_data(event):
    if event["event_type"] == 9:
        event["command"] = " ".join(event["event"]["exec"]["args"])
    event["ppid"] = event["process"]["ppid"]
    event["rpid"] = event["process"]["responsible_audit_token"]["pid"]
    if event["ppid"] == 1:
        event["pcommand"] = "/sbin/launchd"
    else:
        get_pps = subprocess.Popen(
            ["ps", "-p", str(event["ppid"]), "-o", "command="],
            stdout=subprocess.PIPE,
        )
        event["pcommand"] = get_pps.stdout.read().decode("utf-8").rstrip(" \n")
    if event["ppid"] != event["process"]["original_ppid"]:
        event["oppid"] = event["process"]["original_ppid"]
        get_opps = subprocess.Popen(
            ["ps", "-p", str(event["oppid"]), "-o", "command="],
            stdout=subprocess.PIPE,
        )
        event["opcommand"] = get_opps.stdout.read().decode("utf-8").rstrip(" \n")
    if event["rpid"] == 1:
        event["rcommand"] = "/sbin/launchd"
    else:
        get_rps = subprocess.Popen(
                ["ps", "-p", str(event["rpid"]), "-o", "command="],
                stdout=subprocess.PIPE,
            )
        event["rcommand"] = get_rps.stdout.read().decode("utf-8").rstrip(" \n")
    return event

