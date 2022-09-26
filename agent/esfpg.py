#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    Take output from ESF Playground and insert into a unique mongo db
    using a connection string via commandline to designate server

    Modify the path of ESFPlayground if needed

    The new versions of ESFPlayground let you choose which events to output through the UI
    you may need to modify those settings to get the correct output

    Example usage: sudo python3 esfpg2mongodb.py mongodb://127.0.0.1:27017

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
from re import sub
import sys
import os
import subprocess
import json
import hashlib
from database import DatabaseConnection
from bson.objectid import ObjectId
from utility import format_event, get_event_string
from agent_config import MONGO_CONNECTION_STRING, ESFPG


AGENT_PID = os.getpid()

EXCLUDED_PROC_PATHS = [
    "/usr/libexec/endpointsecurityd",
    "/private/var/run/mDNSResponder",
    "/usr/libexec/logd_helper",
    # "/usr/libexec/airportd",
    # "/Applications/iTerm.app/Contents/MacOS/iTerm2",
]


class ESFWrapper:
    def __init__(self, job_id, parent_pid):
        self.job_id = job_id
        self.parent_pid = int(parent_pid)
        self.ignored_good_events = 0
        self.ignored_proc_paths = 0
        self.db = DatabaseConnection(MONGO_CONNECTION_STRING, job_id)
        self.db.esfriend_jobs.update_one(
            {"_id": ObjectId(self.job_id)}, {"$set": {"agent_pid": AGENT_PID}}
        )
        self.get_goodlist()
        self.run_esf_playground()

    def get_goodlist(self):
        good_dicts = self.db.esfriend["goodlist"].find(
            {"event_md5": {"$exists": True}}, {"event_md5": 1}
        )
        self.goodlist = []
        for good_dict in good_dicts:
            self.goodlist.append(good_dict["event_md5"])

    def insert_event(self, line):
        event = json.loads(line)
        # Quick check to ignore ps commands executed by format_event function
        if "process" in event.keys() and "command" in event["process"].keys():
            if (
                "ps -p" in event["process"]["command"]
                and "-o command=" in event["process"]["command"]
            ):
                return
        # format additional fields for process events
        # flatten unique dictionary into main event dict
        event = format_event(event)
        event_keys = event.keys()
        # exclude proc_path values that should not exhibit malicious behavior
        if "proc_path" in event_keys:
            if event["proc_path"] in EXCLUDED_PROC_PATHS:
                self.ignored_proc_paths += 1
                return
        if "ppid_command" in event_keys:
            if "esfpg.py" in event["ppid_command"]:
                return
        event_string = get_event_string(event)
        event_md5 = hashlib.md5(event_string.encode("utf-8")).hexdigest()
        if event_md5 not in self.goodlist:
            self.db.job.insert_one(event)
        else:
            self.ignored_good_events += 1

    def run_esf_playground(self):
        try:
            esfplayground = subprocess.Popen([ESFPG], stdout=subprocess.PIPE)
            for line in iter(esfplayground.stdout.readline, ""):
                self.insert_event(line)
        except KeyboardInterrupt:
            self.db.esfriend_jobs.update_one(
                {"_id": ObjectId(self.job_id)},
                {
                    "$set": {
                        "ignored_good_events": self.ignored_good_events,
                        "ignored_proc_paths": self.ignored_proc_paths,
                    }
                },
            )
            self.db.client.close()
            print("Ending ESFPlayground.")
            sys.exit()


if __name__ == "__main__":
    job_id = sys.argv[1]
    parent_pid = sys.argv[2]
    ESFWrapper(job_id, parent_pid)
