#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    wrapping eslogger for macOS Ventura and greater

    this script must now be called with sudo to allow collection of all files modified

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
from utility import get_process_data, sha256sum


ESLOGGER_PID = os.getpid()

EXCLUDED_EVENTS = [
    # we gather a list of supported events from eslogger
    # this is a list of event types that should be excluded, if desired
]

class ESLogger(object):
    def __init__(self, job_id, parent_pid):
        self.job_id = job_id
        self.parent_pid = parent_pid
        self.db = DatabaseConnection(MONGO_CONNECTION_STRING, self.job_id)
        self.db.esfriend_jobs.update_one(
            {"_id": ObjectId(self.job_id)}, {"$set": {"eslogger_pid": ESLOGGER_PID, "agent_pid": self.parent_pid}}
        )
        self.get_supported_events()
        self.run_eslogger()

    def get_supported_events(self):
        eslogger_command = [ESLOGGER, "--list-events"]
        eslogger_exec = subprocess.Popen(eslogger_command, stdout=subprocess.PIPE)
        self.supported_events = eslogger_exec.communicate()[0].decode().split("\n")
        del self.supported_events[-1]
        for event_type in EXCLUDED_EVENTS:
            self.supported_events.remove(event_type)

    def run_eslogger(self):
        try:
            eslogger_command = ["/usr/bin/sudo", ESLOGGER]
            eslogger_command += self.supported_events
            eslogger_exec = subprocess.Popen(eslogger_command, stdout=subprocess.PIPE)
            # print(" ".join(eslogger_command))
            for line in iter(eslogger_exec.stdout.readline, ""):
                self.insert_event(line)
        except KeyboardInterrupt:
            self.db.client.close()
            print("Ending eslogger.")
            sys.exit()

    def insert_event(self, line):
        event = json.loads(line)
        if not event["process"]["is_es_client"]:
            event["pid"] = event["process"]["audit_token"]["pid"]
            event["process_path"] = event["process"]["executable"]["path"]
            event["event_type_description"] = list(event["event"].keys())[0]
            event = get_process_data(event)
            self.db.eslog.insert_one(event)
            if event["event_type_description"] == "close" and event["event"]["close"]["modified"]:
                # do file stuff
                if event["event"]["close"]["target"]["stat"]["st_size"] > 0:
                    # get checksum/file_type, upload file, add file upload record
                    try:
                        file_sha256 = sha256sum(event["close"]["target"]["path"])
                        file_type_command = ["file", event["event"]["close"]["target"]["path"]]
                        file_type_exec = subprocess.Popen(
                            file_type_command,
                            stdout=subprocess.PIPE
                        )
                        file_type = file_type_exec.stdout.read().decode("utf-8").rstrip(" \n")
                        file_id = self.db.insert_file_with_file_path(event["event"]["close"]["target"]["path"])
                        file_dict = {
                            "file_sha256": file_sha256,
                            "file_type": file_type,
                            "file_path": event["event"]["close"]["target"]["path"],
                            "file_size": event["event"]["close"]["target"]["stat"]["st_size"],
                            "pcommand": event["pcommand"],
                            "rcommand": event["rcommand"],
                            "file_id": file_id,
                        }
                        self.db.files.insert_one(file_dict)
                    except Exception as err:
                        file_dict = {
                            "file_path": event["event"]["close"]["target"]["path"],
                            "file_size": event["event"]["close"]["target"]["stat"]["st_size"],
                            "pcommand": event["pcommand"],
                            "rcommand": event["rcommand"],
                            "error": "{}".format(err)
                        }



if __name__ == "__main__":
    job_id = sys.argv[1]
    parent_pid = sys.argv[2]
    eslogger = ESLogger(job_id, parent_pid)