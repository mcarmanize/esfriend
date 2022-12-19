#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    Collect additional information with system log streaming

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
from agent_config import MONGO_CONNECTION_STRING
import traceback

LOGSTREAM_PID = os.getpid()

class LogStreamWrapper:
    def __init__(self, job_id):
        self.job_id = job_id
        self.db = DatabaseConnection(MONGO_CONNECTION_STRING, job_id)
        self.db.esfriend_jobs.update_one({"_id": ObjectId(self.job_id)}, {"$set": {"logstream_pid": LOGSTREAM_PID}})
        self.run_logstream()

    def insert_log_message(self, message):
        try:
            message_json = json.loads(message)
            # traceID can be an int value that mongodb cannot accept
            message_json["traceID"] = str(message_json["traceID"])
            if message_json["subsystem"] == "":
                message_json["subsystem"] = "None"
            self.db.syslog.insert_one(message_json)
        except Exception as err:
            traceback.print_exc()
            print(message)

    def run_logstream(self):
        try:
            logstream_command = ["/usr/bin/log", "stream", "--style", "ndjson", "--debug"]
            logstream_process = subprocess.Popen(logstream_command, stdout=subprocess.PIPE)
            for line in iter(logstream_process.stdout.readline, ""):
                self.insert_log_message(line)
        except KeyboardInterrupt:
            self.db.client.close()
            print("Ending log stream.")
            sys.exit()

if __name__ == "__main__":
    job_id = sys.argv[1]
    LogStreamWrapper(job_id)