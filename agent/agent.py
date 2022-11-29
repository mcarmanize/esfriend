#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    This agent runs on the sandbox machine

    See README.md for system setup

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
import time
import subprocess
import signal
from database import DatabaseConnection
from utility import p7z, find_app_in_tmp, add_x_flag
from agent_config import MACHINE_NAME, MACHINE_TYPE, MONGO_CONNECTION_STRING

AGENT_PID = os.getpid()


class ESFriendAgent:
    def __init__(self):
        self.start_time = None
        self.job = None
        self.get_job()

    def get_job(self):
        while True:
            # check if the machine has been assigned a job
            if self.job is None:
                db = DatabaseConnection(MONGO_CONNECTION_STRING)
                self.machine_data = db.esfriend_machines.find_one(
                    {"machine_name": MACHINE_NAME}
                )
                if self.machine_data is None:
                    # esfriend database does not have machine record
                    # this condition is met when esfriend has been cleaned or the database is unavailable
                    db.client.close()
                elif (
                    "assigned_job" in self.machine_data
                    and self.machine_data["assigned_job"] is not None
                ):
                    self.job = self.machine_data["assigned_job"]
                    # get job data from the database
                    job_data = db.esfriend_jobs.find_one({"_id": self.job})
                    print(job_data)
                    # quick check to ensure we're not picking up a job already run
                    if job_data["job_progress"] == 1:
                        # set the job progress to 2 so that the esfriend agent can start mitmproxy
                        # on the configured port
                        set_mitm = db.esfriend_jobs.update_one(
                            {"_id": self.job}, {"$set": {"job_progress": 2}}
                        )
                        self.job_id = job_data["_id"]
                        self.file_id = job_data["file_id"]
                        self.file_name = job_data["file_name"]
                        self.sha256 = job_data["sha256"]
                        self.timeout = job_data["timeout"]
                        db.client.close()
                        self.run_job()
                    else:
                        # this branch of code catches when a previous run errored out and was not able to clean up
                        # we unassign the job to move onto the next
                        unassign_job = db.esfriend_machines.update_one(
                            {"machine_name": MACHINE_NAME},
                            {"$set": {"assigned_job": None}},
                        )
                        set_error = db.esfriend_jobs.update_one(
                            {"_id": self.job},
                            {
                                "$set": {
                                    "error": "Expected job progress 1 - run aborted"
                                }
                            },
                        )
                        db.client.close()
                        self.job = None
                        # setting the start time here forces a reboot in 3 seconds
                        # self.start_time = int(time.time()) - (self.timeout + 3)
                else:
                    # mongodb is running but no job assigned
                    db.client.close()
            self.wait_for_timeout()
            time.sleep(5)

    def run_job(self):
        db = DatabaseConnection(MONGO_CONNECTION_STRING)
        file_data = db.get_file(self.file_id)
        self.file_path = os.path.join("/tmp", self.file_name)
        with open(self.file_path, "wb") as f:
            f.write(file_data)
            f.close()
        db.client.close()
        eslogger_command = ["./eslogger.py", str(self.job_id), str(AGENT_PID)]
        log_command = ["./log.py", str(self.job_id)]
        self.eslogger_process = subprocess.Popen(eslogger_command)
        self.log_process = subprocess.Popen(log_command)
        # this sleep allows the system running ESFriend to start mitmdump in time
        time.sleep(5)
        self.start_time = int(time.time())
        # The next step is to launch the malware and record the results
        # for the specified amount of time
        self.check_file_packaging()
        self.execute_package()

    def check_file_packaging(self):
        # examine the file extension to see if we can launch the file automatically
        self.supported_extensions = [
            ".app.zip",  # app bundle
            ".dmg",  # disk image
            ".sh",  # shell script
            ".scpt",  # apple script
            ".o",  # MachO file
        ]
        self.package_type = None
        for ext in self.supported_extensions:
            if self.file_name.endswith(ext):
                self.package_type = ext

    def execute_package(self):
        if self.package_type == ".app.zip":
            p7z(self.file_path)
            self.extacted_app_path = find_app_in_tmp()
            if self.extacted_app_path is not None:
                app_command = ["/usr/bin/open", self.extacted_app_path]
                app_execute = subprocess.Popen(
                    app_command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
            else:
                open_temp = subprocess.Popen(["/usr/bin/open", "/tmp"])
        elif self.package_type == ".dmg":
            dmg_command = ["/usr/bin/open", self.file_path]
            dmg_mount = subprocess.Popen(dmg_command)
        elif self.package_type == ".sh":
            x_flag_set = add_x_flag(self.file_path)
            if x_flag_set:
                self.output = open("output.txt", "w")
                sh_execute = subprocess.Popen(
                    [self.file_path], stdout=self.output, stderr=self.output
                )
            else:
                open_temp = subprocess.Popen(["open", "/tmp"])
        elif self.package_type == ".scpt":
            scpt_command = ["/usr/bin/osascript", self.file_path]
            self.output = open("output.txt", "w")
            scpt_execute = subprocess.Popen(
                scpt_command, stdout=self.output, stderr=self.output
            )
            scpt_execute.communicate()
        elif self.package_type == ".o":
            x_flag_set = add_x_flag(self.file_path)
            macho_command = [self.file_path]
            if x_flag_set:
                self.output = open("output.txt", "w")
                macho_execute = subprocess.Popen(
                    macho_command, stdout=self.output, stderr=self.output
                )
                macho_execute.communicate()
        else:
            open_temp = subprocess.Popen(["/usr/bin/open", "/tmp"])

    def wait_for_timeout(self):
        if self.start_time is not None:
            now = int(time.time())
            if (now - self.start_time) > self.timeout:
                self.eslogger_process.send_signal(signal.SIGINT)
                self.log_process.send_signal(signal.SIGINT)
                db = DatabaseConnection(MONGO_CONNECTION_STRING)
                unassign_job = db.esfriend_machines.update_one(
                    {"machine_name": MACHINE_NAME}, {"$set": {"assigned_job": None}}
                )
                if os.path.exists("output.txt"):
                    output_upload = db.insert_file_with_file_path("output.txt")
                    add_output_id = db.esfriend_jobs.update_one(
                        {"_id": self.job_id},
                        {"$set": {"output_file_id": output_upload}},
                    )
                set_analysis_flag = db.esfriend_jobs.update_one(
                    {"_id": self.job_id}, {"$set": {"job_progress": 4}}
                )
                db.client.close()
                time.sleep(5)
                subprocess.Popen(["sudo", "/sbin/reboot"])


if __name__ == "__main__":
    ESFriendAgent()
