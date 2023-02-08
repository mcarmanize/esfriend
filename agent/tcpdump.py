#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    tcpdump wrapper

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
import subprocess
import time
import socket
from database import DatabaseConnection
from bson.objectid import ObjectId
from agent_config import MONGO_CONNECTION_STRING, TCPDUMP, ESFRIEND_SERVER_IP, ESFRIEND_SERVER_PORT


TCPDUMP_PID = os.getpid()


class TcpdumpWrapper(object):
    def __init__(self, job_id) -> None:
        self.job_id = job_id
        self.machine_ip = socket.gethostbyname(socket.gethostname())
        self.db = DatabaseConnection(MONGO_CONNECTION_STRING, self.job_id)
        self.db.esfriend_jobs.update_one(
            {"_id": ObjectId(self.job_id)}, {"$set": {"tcpdump_pid": TCPDUMP_PID}}
        )
        self.db.client.close()
        self.run_tcpdump_exec()

    def run_tcpdump_exec(self):
        try:
            tcpdump_command = ["/usr/bin/sudo", TCPDUMP, "-w", "tcpdump.out"]
            tcpdump_command += ["host", self.machine_ip]
            # hopefully ignore traffic to the mongodb server?
            tcpdump_command += [
                "and", "not", "(",
                "dst", "host", ESFRIEND_SERVER_IP, "and",
                "dst", "port", ESFRIEND_SERVER_PORT,
                ")", "and", "not", "(",
                "src", "host", ESFRIEND_SERVER_IP, "and",
                "src", "port", ESFRIEND_SERVER_PORT,
                ")"

            ]
            print(tcpdump_command)
            tcpdump_exec = subprocess.Popen(tcpdump_command, stdout=subprocess.PIPE)
            while True:
                # wait for keyboard interrupt
                time.sleep(5)
        except KeyboardInterrupt:
            tcpdump_exec.terminate()
            self.db = DatabaseConnection(MONGO_CONNECTION_STRING, self.job_id)
            file_id = self.db.insert_file_with_file_path("tcpdump.out")
            os.remove("tcpdump.out")
            self.db.esfriend_jobs.update_one({"_id": ObjectId(self.job_id)}, {"$set": {"tcpdump_file": file_id}})
            self.db.client.close()
            print("Stopping tcpdump.")
            sys.exi
if __name__ == "__main__":
    job_id = sys.argv[1]
    TcpdumpWrapper(job_id)