#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    wrapping eslogger for macOS Ventura and greater


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

import sys
import os
import subprocess
import json
from database import DatabaseConnection
from bson.objectid import ObjectId
from agent_config import MONGO_CONNECTION_STRING, ESLOGGER
from utility import sha256sum, get_pid_command, get_file_type
import traceback


ESLOGGER_CLOSE_PID = os.getpid()

EXCLUDED_DIRS = [
    "/private/var/log/com.apple.xpc.launchd",
]


class CloseLogger(object):
    def __init__(self, job_id) -> None:
        self.job_id = job_id
        self.db = DatabaseConnection(MONGO_CONNECTION_STRING, self.job_id)
        self.db.esfriend_jobs.update_one(
            {"_id": ObjectId(self.job_id)}, {"$set": {"eslogger_close_pid": ESLOGGER_CLOSE_PID}}
        )
        self.run_eslogger_close()

    def get_process_data(self, event):
        event["ppid"] = event["process"]["ppid"]
        event["rpid"] = event["process"]["responsible_audit_token"]["pid"]
        if event["ppid"] == 1:
            event["pcommand"] = "/sbin/launchd"
        else:
            event["pcommand"] = get_pid_command(event["ppid"])
        if event["ppid"] != event["process"]["original_ppid"]:
            # this condition should not be met, but catching in case
            event["oppid"] = event["process"]["original_ppid"]
            event["opcommand"] = get_pid_command(event["oppid"])
        if event["rpid"] == 1:
            event["rcommand"] = "/sbin/launchd"
        else:
            event["rcommand"] = get_pid_command(event["rpid"])
        return event

    def insert_event(self, line):
        try:
            event = json.loads(line)
            if not event["process"]["is_es_client"] and os.path.dirname(event["event"]["close"]["target"]["path"]) not in EXCLUDED_DIRS:
                event["pid"] = event["process"]["audit_token"]["pid"]
                event["process_path"] = event["process"]["executable"]["path"]
                event["event_type_description"] = list(event["event"].keys())[0]
                event = self.get_process_data(event)
                if event["event"]["close"]["modified"] and event["event"]["close"]["target"]["stat"]["st_size"] > 0:
                    print("Uploading: {}".format(event["event"]["close"]["target"]["path"]))
                    try:
                        file_sha256 = sha256sum(event["event"]["close"]["target"]["path"])
                        file_type = get_file_type(event["event"]["close"]["target"]["path"])
                        file_id = self.db.insert_file_with_file_path(event["event"]["close"]["target"]["path"])
                        file_dict = {
                            "file_sha256": file_sha256,
                            "file_type": file_type,
                            "file_path": event["event"]["close"]["target"]["path"],
                            "file_size": event["event"]["close"]["target"]["stat"]["st_size"],
                            "pcommand": event["pcommand"],
                            "rcommand": event["rcommand"],
                            "file_id": file_id,
                            "upload_success": True
                        }
                        self.db.files.insert_one(file_dict)
                    except Exception as err:
                        print(err)
                        file_dict = {
                            "file_path": event["event"]["close"]["target"]["path"],
                            "file_size": event["event"]["close"]["target"]["stat"]["st_size"],
                            "pcommand": event["pcommand"],
                            "rcommand": event["rcommand"],
                            "error": "{}".format(err),
                            "upload_success": False
                        }
                        self.db.files.insert_one(file_dict)
                self.db.eslog.insert_one(event)
        except Exception as err:
            traceback.print_exc()
            print(line)

    def run_eslogger_close(self):
        try:
            eslogger_command = ["/usr/bin/sudo", ESLOGGER, "close"]
            eslogger_exec = subprocess.Popen(eslogger_command, stdout=subprocess.PIPE)
            for line in iter(eslogger_exec.stdout.readline, ""):
                if len(line) > 0:
                    self.insert_event(line)
        except KeyboardInterrupt:
            eslogger_exec.kill()
            self.db.client.close()
            print("Stopping 'close' event stream.")
            sys.exit()


if __name__ == "__main__":
    job_id = sys.argv[1]
    CloseLogger(job_id)