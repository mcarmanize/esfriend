#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    Perform analysis of events and network traffic after collection
    Generate report and insert it into the the appropriate job record

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
import sys
import subprocess
import json
import hashlib
from database import DatabaseConnection
from bson.objectid import ObjectId
from config import MITMDUMP
from process_list import RunLogAnalyzer
from utility import get_event_string, normalize_filemon_event, FILEMON_EVENTS
import traceback


class Analyze:
    def __init__(self, job_id):
        self.job_id = job_id
        self.pcap_path = os.path.join("pcap", self.job_id)
        self.db = DatabaseConnection()
        
        # add message_md5 field to all messages in the log database
        self.db.add_message_md5(self.job_id)
        self.report = {}
        self.job_data = self.db.esfriend_jobs.find_one({"_id": ObjectId(self.job_id)})
        if "output_file_id" in self.job_data.keys():
            self.output_file_id = self.job_data["output_file_id"]
            output_file = self.db.get_file(self.output_file_id)
            self.report["output"] = output_file.decode()
        else:
            self.report["output"] = ""
        self.analyze_run()
        report_string = json.dumps(self.report)
        report_id = self.db.insert_string(report_string)
        update_job_data = self.db.esfriend_jobs.update_one(
            {"_id": ObjectId(self.job_id)}, {"$set": {"report_id": report_id}}
        )

    def analyze_run(self):
        try:
            if os.path.exists(self.pcap_path):
                mitm_command = [
                    MITMDUMP,
                    "-s",
                    "save_headers.py",
                    "-r",
                    self.pcap_path,
                    "-p",
                    "8091",
                ]
                mitm_execute = subprocess.Popen(mitm_command, stdout=subprocess.DEVNULL)
                mitm_execute.wait()
                request_headers = open("request_headers.txt", "r").read()
                request_headers = request_headers.replace("\n", "<br>")
                self.report["request_headers"] = request_headers
                # delete the headers file and mitmdump file from disk
                os.remove("request_headers.txt")
                os.remove(self.pcap_path)
            else:
                self.report["request_headers"] = None
        except Exception:
            traceback.print_exc()
        proc_list_obj = RunLogAnalyzer(self.job_id)
        proc_tree = proc_list_obj.process_tree
        self.report["proc_list"] = proc_tree
        self.apply_goodlist()
        print(f"Analysis finished for job id: {self.job_id}")  

    def apply_goodlist(self):
        es_collection = self.job_id+"eslog"
        ls_collection = self.job_id+"syslog"
        self.db.run_logs[es_collection].create_index("goodlist")
        self.db.run_logs[ls_collection].create_index("goodlist")
        es_cursor = self.db.run_logs[es_collection].find()
        for event in es_cursor:
            if event["event_type_description"] in FILEMON_EVENTS:
                event = normalize_filemon_event(event)
                if event["event_type_description"] == "close":
                    self.db.run_logs[es_collection].update_one(
                        {"_id": event["_id"]}, 
                        {
                            "$set": {
                                "modified": event["modified"], 
                                "process_path": event["process_path"]
                            }
                        }
                    )
                else:
                    self.db.run_logs[es_collection].update_one(
                        {"_id": event["_id"]}, 
                        {
                            "$set": {
                                "process_path": event["process_path"]
                            }
                        }
                    )
            event_string = get_event_string(event)
            event_md5 = hashlib.md5(event_string.encode("utf-8")).hexdigest()
            good_event = self.db.esfriend["esgoodlist"].find_one({"event_md5": event_md5})
            if good_event is None:
                self.db.run_logs[es_collection].update_one({"_id": event["_id"]}, {"$set": {"goodlist": False}})
            else:
                self.db.run_logs[es_collection].update_one({"_id": event["_id"]}, {"$set": {"goodlist": True}})
        ls_cursor = self.db.run_logs[ls_collection].find()
        for event in ls_cursor:
            good_event = self.db.esfriend["lsgoodlist"].find_one({"message_md5": event["message_md5"]})
            if good_event is None:
                self.db.run_logs[ls_collection].update_one({"_id": event["_id"]}, {"$set": {"goodlist": False}})
            else:
                self.db.run_logs[ls_collection].update_one({"_id": event["_id"]}, {"$set": {"goodlist": True}})
        

if __name__ == "__main__":
    job_id = sys.argv[1]
    Analyze(job_id)
