#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    generate or print a process list for the results page

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
from pymongo import MongoClient
from bson.objectid import ObjectId
from config import MONGO_CONNECTION_STRING


class DatabaseConnection:
    def __init__(self, connection_string):
        try:
            self.client = MongoClient(connection_string)
            self.run_logs = self.client.run_logs
        except Exception as err:
            print(err)


class RunLogAnalyzer:
    def __init__(self, job_id=None):
        self.db = DatabaseConnection(MONGO_CONNECTION_STRING)
        if job_id is None:
            self.select_run_log()
        else:
            self.selected_collection = job_id+"eslog"
            self.generate_process_tree()

    def select_run_log(self):
        self.runs = self.db.client.esfriend["jobs"].find()
        os.system("clear")
        collection_index = 0
        collection_name_list = []
        print("\n   Select run to analyze:\n")
        for run in self.runs:
            if run["job_progress"] == 5:
                collection_name = str(run["_id"])+"eslog"
                file_name = run["file_name"]
                timeout = run["timeout"]
                tags = run["tags"]
                collection_name_list.append(collection_name)
                print(f"  {collection_index}: {file_name} {timeout} {tags}")
                collection_index += 1
        selection = int(input("\n    Enter a number: "))
        self.selected_collection = collection_name_list[selection]
        self.print_process_tree()

    def add_process(self, pid, command, pcommand="", rcommand=""):
        if pid not in self.process_tree.keys():
            self.process_tree[pid] = {}
            self.process_tree[pid]["command"] = command
            self.process_tree[pid]["pcommand"] = pcommand
            self.process_tree[pid]["rcommand"] = rcommand
            self.process_tree[pid]["children"] = list()

    def generate_process_tree(self):
        self.parse_cursor()
        self.sorted_processes = sorted(self.process_tree.keys())

    def print_process_tree(self):
        self.parse_cursor()
        self.printed = []
        self.sorted_processes = sorted(self.process_tree.keys())
        for pid in self.sorted_processes:
            if pid not in self.printed:
                self.printed.append(pid)
                print("Parent")
                print(pid, self.process_tree[pid]["command"])
                print("Children")
                self.print_children(pid)
                print("-----------")

    def print_children(self, key):
        for child in self.process_tree[key]["children"]:
            if child not in self.printed:
                self.printed.append(child)
                print(
                    child,
                    self.process_tree[child]["command"],
                    "<<<",
                    self.process_tree[child]["rcommand"],
                )
                self.print_children(child)

    def parse_cursor(self):
        self.process_tree = {}
        cursor = self.db.run_logs[self.selected_collection].find(
            {
                "$or": [
                    {"event_type_description": "exec"},
                    # {"event_type_description": "fork"},
                    # {"event_type_description": "exit"}
                ]
            }
        )
        for item in cursor:
            # Original ppid and ppid look to be the same in most cases.
            item_keys = item.keys()
            if "rcommand" in item_keys and "pcommand" in item_keys:
                self.add_process(item["pid"], item["command"], item["pcommand"], item["rcommand"])
                # self.process_tree[item["ppid"]]["children"].append(item["pid"])
            elif "rcommand" in item_keys:
                self.add_process(
                    item["pid"], item["command"], rcommand=item["rcommand"]
                )
            elif "pcommand" in item_keys:
                self.add_process(item["ppid"], item["command"], pcommand=item["pcommand"])
                self.process_tree[item["ppid"]]["children"].append(item["pid"])
            else:
                self.add_process(item["pid"], item["command"])


if __name__ == "__main__":
    if len(sys.argv) > 1:
        job_id = sys.argv[1]
        RunLogAnalyzer(job_id=job_id)
    else:
        RunLogAnalyzer()
        # print("Usage: ./process_list.py job_id")
