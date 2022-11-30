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
        self.lsgoodlist.create_index("event_md5")
        self.select_run_log()

    def select_run_log(self):
        # self.collections = self.db.run_logs.list_collections()
        # self.collections = sorted(self.collections, key=lambda d: d["name"])
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
            event_exists = self.lsgoodlist.find_one({"message_md5": message_md5})
            if event_exists is None:
                event_insert = {
                    "event_message": log_event["eventMessage"],
                    "message_md5": message_md5,
                    "message_ssdeep": message_ssdeep,
                }
                self.lsgoodlist.insert_one(event_insert)
        es_cursor = self.db.run_logs[es_collection_name].find()
        for event in es_cursor:
            event_string = self.get_event_string(event)
            event_md5 = hashlib.md5(event_string.encode("utf-8")).hexdigest()
            event_ssdeep = ssdeep.hash(event_string.encode("utf-8"))
            event_exists = self.esgoodlist.find_one({"event_md5": event_md5})
            if event_exists is None:
                event_insert = {
                    "event_string": event_string,
                    "event_md5": event_md5,
                    "event_ssdeep": event_ssdeep,
                }
                self.esgoodlist.insert_one(event_insert)

    def get_event_string(self, event):
        try:
            event_string = "{},{}".format(event["event_type_description"], event["process_path"])
            event_dict = {
                "access": self.access_string,
                "chdir": self.chdir_string,
                "clone": self.clone_string,
                "close": self.close_string,
                "create": self.create_string,
                "dup": self.dup_string,
                "exec": self.exec_string,
                "exit": self.exit_string,
                "fcntl": self.fcntl_string,
                "fork": self.fork_string,
                "fsgetpath": self.fsgetpath_string,
                "get_task": self.get_task_string,
                "get_task_name": self.get_task_name_string,
                "get_task_read": self.get_task_read_string,
                "getattrlist": self.getattrlist_string,
                "getextattr": self.getextattr_string,
                "iokit_open": self.iokit_open_string,
                "listextattr": self.listextattr_string,
                "lookup": self.lookup_string,
                "mmap": self.mmap_string,
                "mprotect": self.mprotect_string,
                "open": self.open_string,
                "proc_check": self.proc_check_string,
                "proc_suspend_resume": self.proc_suspend_resume_string,
                "readdir": self.readdir_string,
                "readlink": self.readlink_string,
                "rename": self.rename_string,
                "setattrlist": self.setattrlist_string,
                "setegid": self.setegid_string,
                "seteuid": self.seteuid_string,
                "setextattr": self.setextattr_string,
                "setgid": self.setgid_string,
                "setmode": self.setmode_string,
                "setowner": self.setowner_string,
                "setuid": self.setuid_string,
                "signal": self.signal_string,
                "stat": self.stat_string,
                "truncate": self.truncate_string,
                "uipc_connect": self.uipc_connect_string,
                "unlink": self.unlink_string,
                "write": self.write_string,
            }
            event_string = event_dict[event["event_type_description"]](event_string, event)
            return event_string
        except Exception as err:
            print(f"{err}\n{event}\n")
            return ""

    """
        each event has a function to process contents
        please add in alphabetical order
    """

    def access_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["access"]["target"]["path"],
            event["event"]["access"]["mode"]
        )
        return event_string

    def chdir_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["chdir"]["target"]["path"])
        return event_string
    
    def clone_string(self, event_string, event):
        if "target" in event["event"]["clone"]:
            event_string += ",{},{},{}".format(
                event["event"]["clone"]["source"]["path"],
                event["event"]["clone"]["target"]["path"],
                event["event"]["clone"]["target_name"]
            )
        elif "target_dir" in event["event"]["clone"]:
            event_string += ",{},{},{}".format(
                event["event"]["clone"]["source"]["path"],
                event["event"]["clone"]["target_dir"]["path"],
                event["event"]["clone"]["target_name"]
            )
        return event_string
    
    def close_string(self, event_string, event):
        event_string += ",{},{},{}".format(
            event["event"]["close"]["target"]["path"],
            event["event"]["close"]["modified"],
            event["event"]["close"]["was_mapped_writable"]
        )
        return event_string

    def create_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["create"]["destination"]["existing_file"]["path"],
            event["event"]["create"]["acl"]
        )
        return event_string
    
    def dup_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["dup"]["target"]["path"])
        return event_string
        
    def exec_string(self, event_string, event):
        event_string += ",{},{},{},{}".format(
            event["pcommand"],
            event["rcommand"],
            event["command"],
            event["event"]["exec"]["script"]

        )
        return event_string
    
    def exit_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["exit"]["stat"])
        return event_string

    def fcntl_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["fcntl"]["target"]["path"],
            event["event"]["fcntl"]["cmd"]
        )
        return event_string

    def fork_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["fork"]["child"]["executable"]["path"])
        return event_string

    def fsgetpath_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["fsgetpath"]["target"]["path"])
        return event_string

    def get_task_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["get_task"]["target"]["executable"]["path"],
            event["event"]["get_task"]["type"]
        )
        return event_string    

    def get_task_name_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["get_task_name"]["target"]["executable"]["path"],
            event["event"]["get_task_name"]["type"]
        )
        return event_string

    def get_task_read_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["get_task_read"]["target"]["executable"]["path"],
            event["event"]["get_task_read"]["type"]
        )
        return event_string

    def getattrlist_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["getattrlist"]["target"]["path"])
        return event_string
         
    def getextattr_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["getextattr"]["target"]["path"],
            event["event"]["getextattr"]["extattr"]
        )
        return event_string

    def iokit_open_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["iokit_open"]["user_client_class"],
            event["event"]["iokit_open"]["user_client_type"]
        )
        return event_string

    def listextattr_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["listextattr"]["target"]["path"])
        return event_string

    def lookup_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["lookup"]["source_dir"]["path"],
            event["event"]["lookup"]["relative_target"]
        )
        return event_string

    def mmap_string(self, event_string, event):
        event_string += ",{},{},{},{}".format(
            event["event"]["mmap"]["source"]["path"],
            event["event"]["mmap"]["flags"],
            event["event"]["mmap"]["protection"],
            event["event"]["mmap"]["max_protection"],
        )
        return event_string

    def mprotect_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["mprotect"]["protection"])
        return event_string

    def open_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["open"]["file"]["path"],
            event["event"]['open']["fflag"]
        )
        return event_string

    def proc_check_string(self, event_string, event):
        if event["event"]["proc_check"]["target"] is not None:
            event_string += ",{},{},{}".format(
                event["event"]["proc_check"]["target"]["executable"]["path"],
                event["event"]["proc_check"]["type"],
                event["event"]["proc_check"]["flavor"]
            )
        else:
            event_string += ",{},{}".format(
                event["event"]["proc_check"]["type"],
                event["event"]["proc_check"]["flavor"]
            )
        return event_string

    def proc_suspend_resume_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["proc_suspend_resume"]["target"]["executable"]["path"])
        return event_string

    def readdir_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["readdir"]["target"]["path"])
        return event_string

    def readlink_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["readlink"]["source"]["path"])
        return event_string

    def rename_string(self, event_string, event):
        if "new_path" in event["event"]["rename"]:
            event_string += ",{},{},{},{}".format(
                event["event"]["rename"]["source"]["path"],
                event["event"]["rename"]["new_path"]["dir"],
                event["event"]["rename"]["new_path"]["filename"],
                event["event"]["rename"]["destination_type"]
            )
        elif "existing_file" in event["event"]["rename"]:
            event_string += ",{},{},{},{}".format(
                event["event"]["rename"]["source"]["path"],
                event["event"]["rename"]["existing_file"]["path"],
                event["event"]["rename"]["destination_type"]
            )
        return event_string
    
    def setattrlist_string(self, event_string, event):
        event_string += ",{},{},{},{},{},{}".format(
            event["event"]["setattrlist"]["target"]["path"],
            event["event"]["setattrlist"]["attrlist"]["bitmapcount"],
            event["event"]["setattrlist"]["attrlist"]["commonattr"],
            event["event"]["setattrlist"]["attrlist"]["dirattr"],
            event["event"]["setattrlist"]["attrlist"]["fileattr"],
            event["event"]["setattrlist"]["attrlist"]["forkattr"]
        )
        return event_string

    def setegid_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["setegid"]["egid"])
        return event_string

    def seteuid_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["seteuid"]["euid"])
        return event_string

    def setextattr_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["setextattr"]["target"]["path"],
            event["event"]["setextattr"]["extattr"]
        )
        return event_string

    def setgid_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["setgid"]["gid"])
        return event_string

    def setmode_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["setmode"]["target"]["path"],
            event["event"]["setmode"]["mode"]
        )
        return event_string

    def setowner_string(self, event_string, event):
        event_string += ",{},{},{}".format(
            event["event"]["setowner"]["target"]["path"],
            event["event"]["setowner"]["uid"],
            event["event"]["setowner"]["gid"]
        )
        return event_string

    def setuid_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["setuid"]["uid"])
        return event_string

    def signal_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["signal"]["sig"],
            event["event"]["signal"]["target"]["executable"]["path"]
        )
        return event_string

    def stat_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["stat"]["target"]["path"])
        return event_string

    def truncate_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["truncate"]["target"]["path"])
        return event_string

    def uipc_connect_string(self, event_string, event):
        event_string += ",{},{},{},{}".format(
            event["event"]["uipc_connect"]["file"]["path"],
            event["event"]["uipc_connect"]["domain"],
            event["event"]["uipc_connect"]["protocol"],
            event["event"]["uipc_connect"]["type"]
        )
        return event_string

    def unlink_string(self, event_string, event):
        event_string += ",{},{}".format(
            event["event"]["unlink"]["target"]["path"],
            event["event"]["unlink"]["parent_dir"]["path"]
        )
        return event_string

    def write_string(self, event_string, event):
        event_string += ",{}".format(event["event"]["write"]["target"]["path"])
        return event_string


if __name__ == "__main__":
    import time
    start = int(time.time())
    GoodList()
    print("Took {} seconds".format(int(time.time()) - start))
