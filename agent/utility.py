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

def get_file_data(event):
    pass

"""
    This is a mess without running with sudo (for both checksum and upload)
    I'm depending on network traffic to track any new files downloaded to the system
    Will need to depend on unpacking data from included resources if I can at least track new files
"""

class FileChangeMonitor:
    def __init__(self, job_id):
        self.job_id = job_id
        self.file_changes = {}
        self.file_changes["fcm"] = True

    def add(self, message):
        if message["event"] == "ES_EVENT_TYPE_NOTIFY_OPEN":
            self.add_open(
                message["file"]["destination"],
                message["file"]["pid"],
                message["file"]["proc_path"],
            )
        if message["event"] == "ES_EVENT_TYPE_NOTIFY_WRITE":
            self.add_write(
                message["file"]["destination"],
                message["file"]["pid"],
                message["file"]["proc_path"],
            )
        if message["event"] == "ES_EVENT_TYPE_NOTIFY_CLOSE":
            self.add_close(
                message["file"]["destination"],
                message["file"]["pid"],
                message["file"]["proc_path"],
            )

    def add_open(self, file, responsible_pid, responsible_path):
        sresponsible_pid = str(responsible_pid)
        if file not in self.file_changes.keys():
            # new file to track modifications
            # saving the checksum of the file before any modificaiton would be preferred, but unattainable with python
            # in practice an antimalware agent would have done a scan of the system and have a database with
            # information about all files on the system
            self.file_changes[file] = {}
            self.file_changes[file]["manipulators"] = {}
            self.file_changes[file]["manipulators"][sresponsible_pid] = {
                "write_flag": False,
                "open_count": 1,
                "close_count": 0,
                "responsible_path": responsible_path,
                "responsible_sha256": sha256sum(responsible_path),
                "previous_victim_sha256": [],
            }
        else:
            # not a new file, new manipulator?
            if sresponsible_pid not in self.file_changes[file]["manipulators"]:
                # new manipulator
                self.file_changes[file]["manipulators"][sresponsible_pid] = {
                    "write_flag": False,
                    "open_count": 1,
                    "close_count": 0,
                    "responsible_path": responsible_path,
                    "responsible_sha256": sha256sum(responsible_path),
                    "previous_victim_sha256": [],
                }
            else:
                # increment open count, preserve previous checksum
                self.file_changes[file]["manipulators"][sresponsible_pid][
                    "open_count"
                ] += 1
                if (
                    "victim_sha256"
                    in self.file_changes[file]["manipulators"][sresponsible_pid].keys()
                ):
                    self.file_changes[file]["manipulators"][sresponsible_pid][
                        "previous_victim_sha256"
                    ].append(
                        self.file_changes[file]["manipulators"][sresponsible_pid][
                            "victim_sha256"
                        ]
                    )

    def add_write(self, file, responsible_pid, responsible_path):
        sresponsible_pid = str(responsible_pid)
        if file not in self.file_changes.keys():
            # File open was not registered, create new entry
            self.file_changes[file] = {}
            self.file_changes[file]["manipulators"] = {}
            self.file_changes[file]["manipulators"][sresponsible_pid] = {
                "write_flag": True,
                "open_count": 1,
                "close_count": 0,
                "responsible_path": responsible_path,
                "responsible_sha256": sha256sum(responsible_path),
                "previous_victim_sha256": [],
            }
        else:
            self.file_changes[file]["manipulators"][sresponsible_pid][
                "write_flag"
            ] = True

    def add_close(self, file, responsible_pid, responsible_path):
        sresponsible_pid = str(responsible_pid)
        if file not in self.file_changes.keys():
            # File open/write was not registered, create new entry, upload file
            # because we don't know if it was written
            self.upload_file(file, responsible_pid, responsible_path)
            self.file_changes[file] = {}
            self.file_changes[file]["manipulators"] = {}
            self.file_changes[file]["manipulators"][sresponsible_pid] = {
                "write_flag": False,
                "open_count": 1,
                "close_count": 1,
                "responsible_path": responsible_path,
                "responsible_sha256": sha256sum(responsible_path),
                "previous_victim_sha256": [],
                "victim_sha256": sha256sum(file),
            }
        else:
            # if self.file_changes[file]["manipulators"][sresponsible_pid]["write_flag"]:
            #     self.upload_file(file, responsible_pid, responsible_path)
            self.file_changes[file]["manipulators"][sresponsible_pid][
                "write_flag"
            ] = False
            self.file_changes[file]["manipulators"][sresponsible_pid][
                "close_count"
            ] += 1
            self.file_changes[file]["manipulators"][sresponsible_pid][
                "victim_sha256"
            ] = sha256sum(file)

    def upload_file(self, file, responsible_pid, responsible_path):
        db = DatabaseConnection(MONGO_CONNECTION_STRING, self.job_id)
        try:
            file_id = db.insert_file_with_file_path(file)
            db.job.insert_one(
                {
                    "file_uploaded": file,
                    "responsible_pid": responsible_pid,
                    "responsible_path": responsible_path,
                    "file_id": file_id,
                }
            )
        except Exception as err:
            db.job.insert_one(
                {
                    "file_uploaded": file,
                    "responsible_pid": responsible_pid,
                    "responsible_path": responsible_path,
                    "file_id_error": f"error: {str(err)}",
                }
            )
        finally:
            db.client.close()
