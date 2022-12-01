#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    goodlist.py - select a scan to add to the goodlist database

    the logic of this script is to process each event into a string
    then hash the string and store both

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

import os
from pymongo import MongoClient
from bson.objectid import ObjectId
import hashlib
import ssdeep
from utility import get_event_string


class DatabaseConnection:
    def __init__(self, connection_string):
        try:
            self.client = MongoClient(connection_string)
            self.jobs = self.client.esfriend["jobs"]
            self.run_logs = self.client.run_logs
        except Exception as err:
            print(err)


class GoodList:
    def __init__(self, selection=None):
        self.db = DatabaseConnection("mongodb://127.0.0.1:27017")
        # endpoint security goodlist
        self.esgoodlist = self.db.client.esfriend["esgoodlist"]
        # log stream goodlist
        self.lsgoodlist = self.db.client.esfriend["lsgoodlist"]
        self.esgoodlist.create_index("event_md5")
        self.lsgoodlist.create_index("message_md5")
        self.select_run_log()

    def select_run_log(self):
        jobs = self.db.jobs.find()
        os.system("clear")
        job_index = 0
        job_list = []
        print("\n   Select job to add to goodlist database:\n")

        for job in jobs:
            if job["job_progress"] == 5:
                file_name = job["file_name"]
                timeout = job["timeout"]
                tags = job["tags"]
                job_list.append(job["_id"])
                print(f"  {job_index}: {file_name} {timeout} {tags}")
                job_index += 1
        selection = int(input("\n    Enter a number: "))
        self.selected_job = job_list[selection]
        self.process_run_logs()

    def process_run_logs(self):
        es_collection_name = str(self.selected_job)+"eslog"
        ls_collection_name = str(self.selected_job)+"syslog"
        ls_cursor = self.db.run_logs[ls_collection_name].find()
        for log_event in ls_cursor:
            message_md5 = hashlib.md5(log_event["eventMessage"].encode("utf-8")).hexdigest()
            message_ssdeep = ssdeep.hash(log_event["eventMessage"].encode("utf-8"))
            event_exists = self.lsgoodlist.find_one({"message_md5": message_md5}) != None
            if not event_exists:
                event_insert = {
                    "event_message": log_event["eventMessage"],
                    "message_md5": message_md5,
                    "message_ssdeep": message_ssdeep,
                }
                self.lsgoodlist.insert_one(event_insert)
        es_cursor = self.db.run_logs[es_collection_name].find()
        for event in es_cursor:
            event_string = get_event_string(event)
            event_md5 = hashlib.md5(event_string.encode("utf-8")).hexdigest()
            event_ssdeep = ssdeep.hash(event_string.encode("utf-8"))
            event_exists = self.esgoodlist.find_one({"event_md5": event_md5}) != None
            if not event_exists:
                event_insert = {
                    "event_string": event_string,
                    "event_md5": event_md5,
                    "event_ssdeep": event_ssdeep,
                }
                self.esgoodlist.insert_one(event_insert)


if __name__ == "__main__":
    import time
    start = int(time.time())
    GoodList()
    print("Took {} seconds".format(int(time.time()) - start))
