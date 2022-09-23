"""
    Methods to interact with the database

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

# import configparser
from pymongo import MongoClient
import gridfs
from config import MONGO_CONNECTION_STRING


class DatabaseConnection:
    def __init__(self):
        try:
            self.client = MongoClient(MONGO_CONNECTION_STRING)
            self.esfriend_grid = self.client.esfriend_grid
            self.esfriend = self.client.esfriend
            self.esfriend_machines = self.esfriend["machines"]
            self.esfriend_jobs = self.esfriend["jobs"]
            self.run_logs = self.client.run_logs
        except Exception as err:
            print(err)

    def insert_file(self, file_path):
        fs = gridfs.GridFS(self.esfriend_grid)
        file_id = fs.put(open(file_path, "rb"))
        return file_id

    def get_file(self, file_id):
        fs = gridfs.GridFS(self.esfriend_grid)
        return fs.get(file_id=file_id).read()

    def get_file_for_download(self, file_id):
        fs = gridfs.GridFS(self.esfriend_grid)
        return fs.get(file_id=file_id)

    def insert_string(self, string):
        fs = gridfs.GridFS(self.esfriend_grid)
        return fs.put(string, encoding="utf-8")
