#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    ESFriend waits for job and assigns them when a machine is available
    It will then wait for a signal to start mitmdump to watch network traffic
    from the machine with the agent running

    If you install the mitmproxy python module, you will need to override the path for mitmdump

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
import time
import subprocess
from database import DatabaseConnection
from machine import Machine
from utility import ping


class ESFriend:
    def __init__(self, clean=False, clean_goods=False):
        if clean is True:
            self.cleanup()
        elif clean_goods is True:
            self.cleanup_with_goodlist()
        else:
            self.machine = Machine()
            self.assign_job()

    def cleanup_with_goodlist(self):
        db = DatabaseConnection()
        db.client.drop_database("esfriend")
        db.client.drop_database("esfriend_grid")
        db.client.drop_database("run_logs")
        db.client.close()

    def cleanup(self):
        db = DatabaseConnection()
        db.esfriend.drop_collection("jobs")
        db.esfriend.drop_collection("machines")
        db.client.drop_database("esfriend_grid")
        db.client.drop_database("run_logs")
        db.client.close()

    def assign_job(self):
        while True:
            self.db = DatabaseConnection()
            self.get_mitm_status()
            self.get_analyze_status()
            self.get_pending_job()
            self.get_idle_machine()
            if self.pending_job is not None and self.idle_machine is not None:
                machine_data = self.db.esfriend_machines.find_one(
                    {"machine_name": self.idle_machine}
                )
                if machine_data["machine_type"] == "physical":
                    ping_result = ping(machine_data["ipaddress"])
                    if ping_result:
                        self.db.esfriend_machines.update_one(
                            {"machine_name": self.idle_machine},
                            {"$set": {"assigned_job": self.pending_job}},
                        )
                        self.db.esfriend_jobs.update_one(
                            {"_id": self.pending_job},
                            {
                                "$set": {
                                    "job_progress": 1,
                                    "assigned_machine": self.idle_machine,
                                }
                            },
                        )
                elif machine_data["machine_type"] == "virtual":
                    self.db.esfriend_machines.update_one(
                        {"machine_name": self.idle_machine},
                        {"$set": {"assigned_job": self.pending_job}},
                    )
                    self.db.esfriend_jobs.update_one(
                        {"_id": self.pending_job}, {"$set": {"job_progress": 1}}
                    )
                    self.start_vm()
            self.db.client.close()
            time.sleep(5)

    def get_pending_job(self):
        cursor = self.db.esfriend_jobs.find_one({"job_progress": 0})
        if cursor is not None:
            self.pending_job = cursor["_id"]
        else:
            self.pending_job = None

    def get_idle_machine(self):
        cursor = self.db.esfriend_machines.find_one({"assigned_job": None})
        if cursor is not None:
            self.idle_machine = cursor["machine_name"]
        else:
            self.idle_machine = None

    def get_mitm_status(self):
        cursor = self.db.esfriend_jobs.find_one({"job_progress": 2})
        if cursor is not None:
            mitm_job_id = cursor["_id"]
            mitm_machine = cursor["assigned_machine"]
            mitm_timeout = cursor["timeout"]
            mitm_port = self.machine.machines[mitm_machine]["mitm_port"]
            command = ["./mitm.py", str(mitm_job_id), str(mitm_port), str(mitm_timeout)]
            mitm_execute = subprocess.Popen(command)
            self.db.esfriend_jobs.update_one(
                {"_id": mitm_job_id}, {"$set": {"job_progress": 3}}
            )
        else:
            self.pending_mitm = None

    def get_analyze_status(self):
        cursor = self.db.esfriend_jobs.find_one({"job_progress": 4})
        if cursor is not None:
            time.sleep(5)
            analysis_job_id = cursor["_id"]
            command = ["./analyze.py", str(analysis_job_id)]
            analysis_execute = subprocess.Popen(command)
            self.db.esfriend_jobs.update_one(
                {"_id": analysis_job_id}, {"$set": {"job_progress": 5}}
            )


if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--clean":
            ESFriend(clean=True)
        if sys.argv[1] == "--cleangoods":
            ESFriend(clean_goods=True)
    else:
        ESFriend()
