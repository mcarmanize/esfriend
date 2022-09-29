#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    Collect additional information with system log streaming

"""

import sys
import os
import subprocess
import json
from database import DatabaseConnection
from bson.objectid import ObjectId
from agent_config import MONGO_CONNECTION_STRING

LOGSTREAM_PID = os.getpid()

class LogStreamWrapper:
    def __init__(self, job_id):
        self.job_id = job_id
        self.db = DatabaseConnection(MONGO_CONNECTION_STRING, job_id)
        self.db.esfriend_jobs.update_one({"_id": ObjectId(self.job_id)}, {"$set": {"logstream_pid": LOGSTREAM_PID}})
        self.run_logstream()

    def insert_log_message(self, message):
        message_json = json.loads(message)
        self.db.syslog.insert_one(message_json)

    def run_logstream(self):
        try:
            logstream_command = ["/usr/bin/log", "stream", "--style", "ndjson"]
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