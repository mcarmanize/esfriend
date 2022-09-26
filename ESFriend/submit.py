#!/Library/Frameworks/Python.framework/Versions/3.9/bin/python3.9
"""
    add a job to the database with all file information needed

    ./submit file_to_submit timout tag(optional)

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
from database import DatabaseConnection
from utility import sha256sum


def submit_file(file_path, timeout, tag=None):
    db = DatabaseConnection()
    file_id = db.insert_file(file_path)
    file_name = file_path.split("/")[-1]
    sha256 = sha256sum(file_path)
    job = {
        "file_id": file_id,
        "file_name": file_name,
        "sha256": sha256,
        "job_progress": 0,
        "timeout": timeout,
        "assigned_machine": None,
    }
    if tag is not None:
        job["tags"] = tag
    result = db.esfriend_jobs.insert_one(job)
    print(f"{file_path} added to job database")


if __name__ == "__main__":
    try:
        file_to_submit = sys.argv[1]
        timeout = int(sys.argv[2])
        tag = sys.argv[3]
        submit_file(file_to_submit, timeout, tag)
    except:
        print("Usage: ./submit.py file_path timeout tags\n\nAll values required.")
