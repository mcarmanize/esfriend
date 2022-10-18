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


class DatabaseConnection:
    def __init__(self, connection_string):
        try:
            self.client = MongoClient(connection_string)
            self.run_logs = self.client.run_logs
        except Exception as err:
            print(err)


class GoodList:
    def __init__(self, selection=None):
        self.db = DatabaseConnection("mongodb://127.0.0.1:27017")
        self.goodlist = self.db.client.esfriend["goodlist"]
        self.goodlist.create_index("event_md5")
        self.select_run_log()

    def select_run_log(self):
        self.collections = self.db.run_logs.list_collections()
        self.collections = sorted(self.collections, key=lambda d: d["name"])
        os.system("clear")
        collection_index = 0
        collection_name_list = []
        print("\n   Select run to add to goodlist database:\n")

        for collection in self.collections:
            collection_name = collection["name"]
            if not str(collection_name).endswith("syslog") and not str(collection_name).endswith("eslog"):
                job_data = self.db.client.esfriend.jobs.find_one(
                    {"_id": ObjectId(collection_name)}
                )
                file_name = job_data["file_name"]
                timeout = job_data["timeout"]
                if "tags" in job_data.keys():
                    collection_tags = job_data["tags"]
                else:
                    collection_tags = None
                collection_name_list.append(collection_name)
                print(f"  {collection_index}: {file_name} {timeout} {collection_tags}")
                collection_index += 1
        selection = int(input("\n    Enter a number: "))
        self.selected_collection = collection_name_list[selection]
        self.process_run_log()

    def process_run_log(self):
        cursor = self.db.run_logs[self.selected_collection].find(
            {"event": {"$exists": True}}
        )
        for item in cursor:
            if "event" in item.keys():
                event_string = self.get_event_string(item)
                event_md5 = hashlib.md5(event_string.encode("utf-8")).hexdigest()
                event_ssdeep = ssdeep.hash(event_string.encode("utf-8"))
                event_exists = self.goodlist.find_one({"event_md5": event_md5})
                if event_exists is None:
                    event_insert = {
                        "event_string": event_string,
                        "event_md5": event_md5,
                        "event_ssdeep": event_ssdeep,
                    }
                    self.goodlist.insert_one(event_insert)

    def get_event_string(self, event):
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
        except Exception as err:
            print(f"{err}\n{event}\n")
            return ""


if __name__ == "__main__":
    import time
    start = int(time.time())
    GoodList()
    print("Took {} seconds".format(int(time.time()) - start))
