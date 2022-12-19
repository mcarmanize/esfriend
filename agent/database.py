""" 
    Database methods for interacting with GridFS

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

from pymongo import MongoClient, errors
import gridfs


class DatabaseConnection:
    def __init__(self, connection_string, job_id=None):
        self.errors = errors
        self.client = MongoClient(connection_string)
        self.esfriend = self.client.esfriend
        self.esfriend_grid = self.client.esfriend_grid
        self.esfriend_jobs = self.esfriend["jobs"]
        self.esfriend_machines = self.esfriend["machines"]
        if job_id is not None:
            self.run_logs = self.client.run_logs
            self.eslog = self.run_logs[job_id+"eslog"]
            self.eslog.create_index("event_type")
            self.eslog.create_index("pid")
            self.eslog.create_index("process_path")
            self.eslog.create_index("event_type_description")
            self.syslog = self.run_logs[job_id+"syslog"]
            self.syslog.create_index("traceID")
            self.syslog.create_index("eventMessage")
            self.syslog.create_index("eventType")
            self.syslog.create_index("subsystem")
            self.syslog.create_index("category")
            self.syslog.create_index("processImagePath")
            self.syslog.create_index("senderImagePath")
            self.files = self.run_logs[job_id+"files"]
            self.files.create_index("file_sha256")
            

    def insert_file_with_file_path(self, file_path):
        fs = gridfs.GridFS(self.esfriend_grid)
        return fs.put(open(file_path, "rb"))

    def insert_file_with_file_handle(self, file_handle):
        fs = gridfs.GridFS(self.esfriend_grid)
        return fs.put(file_handle)

    def insert_string(self, string):
        fs = gridfs.GridFS(self.esfriend_grid)
        return fs.put(string, encoding="utf-8")

    def get_file(self, file_id):
        fs = gridfs.GridFS(self.esfriend_grid)
        return fs.get(file_id=file_id).read()
