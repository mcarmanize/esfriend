#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    Man in the middle needs to launch mitmdump with the correct port configured for the
    test machine

    Keep track of the timeout so we can exit mitmdump when done
    then upload the output file to the databsae

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
import signal
from database import DatabaseConnection
from bson.objectid import ObjectId
from config import MITMDUMP


class MITM:
    def __init__(self, job_id, port, timeout):
        self.job_id = job_id
        self.port = port
        if not os.path.exists("pcap"):
            os.mkdir("pcap")
        self.pcap_path = os.path.join("pcap", self.job_id)
        # increase the timeout just to make sure we run long enough
        self.timeout = timeout + 10
        self.run_mitm()

    def run_mitm(self):
        self.command = [MITMDUMP, "-q", "-p", self.port, "-w", self.pcap_path]
        print("Starting mitmdump with arguments: {}".format(self.command))
        self.mitm_process = subprocess.Popen(self.command)
        self.start_time = int(time.time())
        self.wait_for_timout()

    def wait_for_timout(self):
        now = int(time.time())
        if (now - self.start_time) >= self.timeout:
            # kill the process upload the log file, delete the log file
            print("Stopping mitmdump with arguments: {}".format(self.command))
            self.mitm_process.send_signal(signal.SIGINT)
            db = DatabaseConnection()
            mitm_file_id = db.insert_file(self.pcap_path)
            # db.run_logs[self.job_id].insert_one({"mitm_file_id": mitm_file_id})
            db.esfriend_jobs.update_one(
                {"_id": ObjectId(self.job_id)}, {"$set": {"mitm_file_id": mitm_file_id}}
            )
            db.client.close()
            sys.exit()
        else:
            time.sleep(5)
            self.wait_for_timout()


if __name__ == "__main__":
    job_id = sys.argv[1]
    port = sys.argv[2]
    timeout = int(sys.argv[3])
    MITM(job_id, port, timeout)
