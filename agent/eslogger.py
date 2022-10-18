#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    wrapping eslogger for macOS Ventura and greater

    it looks like we'll need to 
"""

import sys
import os
import subprocess
import json
import hashlib
from database import DatabaseConnection
from bson.objectid import ObjectId
from agent_config import MONGO_CONNECTION_STRING, ESLOGGER


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
        self.db.run_logs[self.job_id+"eslog"].insert_one(event)


if __name__ == "__main__":
    job_id = sys.argv[1]
    parent_pid = sys.argv[2]
    eslogger = ESLogger(job_id, parent_pid)