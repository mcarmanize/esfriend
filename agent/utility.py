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

def get_event_string(event):
    try:
        event_string = ""
        event_keys = event.keys()
        if "process" in event_keys:
            if (
                "command" in event_keys
                and "ppid_command" in event_keys
                and "responsible_pid_command" in event_keys
            ):
                event_string = "{},{},{},{}".format(
                    event["event"],
                    event["responsible_pid_command"],
                    event["ppid_command"],
                    event["command"],
                )
            elif (
                "command" in event_keys
                and "responsible_pid_command" in event_keys
                and "ppid_command" not in event_keys
            ):
                event_string = "{},{},{}".format(
                    event["event"],
                    event["responsible_pid_command"],
                    event["command"],
                )
            elif (
                "command" in event_keys
                and "ppid_command" in event_keys
                and "responsible_pid_command" not in event_keys
            ):
                event_string = "{},{},{}".format(
                    event["event"],
                    event["responsible_pid_command"],
                    event["ppid_command"],
                )
            # tuning down the filtering for process events that have limited information
            # elif "command" in event_keys:
            #     event_string = "{},{}".format(event["event"], event["command"])
        elif "file" in event_keys:
            if "original" in event_keys:
                event_string = "{},{},{},{}".format(
                    event["event"],
                    event["proc_path"],
                    event["original"],
                    event["destination"],
                )
            else:
                event_string = "{},{},{}".format(
                    event["event"],
                    event["proc_path"],
                    event["destination"],
                )
        elif "xattr" in event_keys:
            if "attribute_name" in event_keys:
                event_string = "{},{},{},{}".format(
                    event["event"],
                    event["proc_path"],
                    event["destination"],
                    event["attribute_name"],
                )
            else:
                event_string = "{},{},{}".format(
                    event["event"],
                    event["proc_path"],
                    event["destination"],
                )
        elif "misc" in event_keys:
            event_string = "{},{},{}".format(
                event["event"], event["proc_path"], event["path"]
            )
        elif "ioKit" in event_keys:
            event_string = "{},{},{},{}".format(
                event["event"],
                event["proc_path"],
                event["iokit_class"],
                event["client_type"],
            )
        elif "mprotect" in event_keys:
            # the additional fields below can be used to process memory in real time on the machines.
            # event["mprotect"]["size"], event["mprotect"]["address"]
            event_string = "{},{},{}".format(
                event["event"],
                event["proc_path"],
                event["protection"],
            )
        elif "uipcConnect" in event_keys:
            event_string = "{},{},{},{},{}".format(
                event["event"],
                event["proc_path"],
                event["path"],
                event["domain"],
                event["protocol_type"],
            )
        elif "signal" in event_keys:
            event_string = "{},{},{},{}".format(
                event["event"],
                event["proc_path"],
                event["target_path"],
                event["sig"],
            )
        elif "acl" in event_keys:
            event_string = "{},{},{},{}".format(
                event["event"],
                event["proc_path"],
                event["path"],
                event["type"],
            )
        if event_string == "":
            print(event)
        return event_string
    except:
        return ""

def format_event(message):
    """
        psutil modules requires sudo, so we use subprocess to call ps
    """
    message_keys = message.keys()
    if "process" in message_keys:
        commands = {}
        message_process_keys = message["process"].keys()
        if "command" not in message_process_keys:
            get_ps = subprocess.Popen(
                ["ps", "-p", str(message["process"]["pid"]), "-o", "command="],
                stdout=subprocess.PIPE,
            )
            pid_command = get_ps.stdout.read()
            message["process"]["command"] = pid_command.decode("utf-8")
        for key in message_process_keys:
            if key == "ppid":
                get_ps = subprocess.Popen(
                    ["ps", "-p", str(message["process"]["ppid"]), "-o", "command="],
                    stdout=subprocess.PIPE,
                )
                ppid_command = get_ps.stdout.read()
                commands["ppid_command"] = ppid_command.decode("utf-8")
            if key == "responsible_pid":
                get_ps = subprocess.Popen(
                    [
                        "ps",
                        "-p",
                        str(message["process"]["responsible_pid"]),
                        "-o",
                        "command=",
                    ],
                    stdout=subprocess.PIPE,
                )
                responsible_pid_command = get_ps.stdout.read()
                commands["responsible_pid_command"] = responsible_pid_command.decode(
                    "utf-8"
                )
        message["process"] = {**message["process"], **commands}
        message = {**message, **message["process"]}
        message["process"] = None
    else:
        for key in message_keys:
            if isinstance(message[key], dict):
                message = {**message, **message[key]}
                message[key] = None
    return message


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
