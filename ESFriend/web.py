"""
    Site to view results of a run

    to run type the following:

    export FLASK_APP=web
    flask run

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
from flask import Flask, render_template, jsonify, send_file
from flask_table import Table, Col, LinkCol
import json
from database import DatabaseConnection
from bson.objectid import ObjectId


class AnalysisTable(Table):
    file_name = LinkCol(
        "Filename", "job", url_kwargs=dict(job_id="job_id"), attr="file_name"
    )
    timeout = Col("Timeout")
    tags = Col("Tags")


class JobData(object):
    def __init__(self, file_name, timeout, tags, job_id):
        self.file_name = file_name
        self.timeout = timeout
        self.tags = tags
        self.job_id = job_id


class ParentTable(Table):
    pid = LinkCol(
        "PID", "proc", url_kwargs=dict(job_id="job_id", pid="pid"), attr="pid"
    )
    command = Col("Command")
    rcommand = Col("Responsible Command")
    job_id = Col("Job ID", show=False)


class ParentData(object):
    def __init__(self, pid, command, rcommand, job_id):
        self.pid = pid
        self.command = command
        self.rcommand = rcommand
        self.job_id = job_id


class PidTable(Table):
    pid = LinkCol(
        "PID", "proc", url_kwargs=dict(job_id="job_id", pid="pid"), attr="pid"
    )
    proc_path = Col("Process")
    job_id = Col("Job ID", show=False)


class PidData(object):
    def __init__(self, pid, proc_path, job_id):
        self.pid = pid
        self.proc_path = proc_path
        self.job_id = job_id


class EventTable(Table):
    pid_event = Col("PID Events")


class EventData(object):
    def __init__(self, pid_event):
        self.pid_event = pid_event


class DistinctTable(Table):
    event_type = LinkCol(
        "Event",
        "events",
        url_kwargs=dict(job_id="job_id", event_type="event_type"),
        attr="event_type",
    )
    count = Col("Count")
    job_id = Col("Job ID", show=False)


class DistinctData(object):
    def __init__(self, event_type, count, job_id):
        self.event_type = event_type
        self.count = count
        self.job_id = job_id


def get_job_list():
    db = DatabaseConnection()
    job_cursor = db.esfriend_jobs.find().sort("_id", 1)
    job_list = []
    for job in job_cursor:
        job_list.append(
            JobData(job["file_name"], job["timeout"], job["tags"], job["_id"])
        )
    db.client.close()
    return job_list


def get_parent_list(proc_list, job_id):
    parent_list = []
    for pid in proc_list:
        parent_list.append(
            ParentData(
                pid, proc_list[pid]["command"], proc_list[pid]["rcommand"], job_id
            )
        )
    return parent_list


def get_distinct_list(job_id):
    db = DatabaseConnection()
    distinct_events = db.run_logs[job_id].distinct("event")
    distinct_list = []
    for event in distinct_events:
        event_count = db.run_logs[job_id].count_documents({"event": event})
        distinct_list.append(DistinctData(event, event_count, job_id))
    return distinct_list


app = Flask("ESFriend Web")


@app.route("/")
def index():
    table = AnalysisTable(get_job_list())
    return render_template("table.html", title="ESFriend Web", table=table)


@app.route("/job/<string:job_id>")
def job(job_id):
    db = DatabaseConnection()
    # report_data = db.run_logs[job_id].find({"report_data": {"$exists": True}})
    job_data = db.esfriend_jobs.find_one({"_id": ObjectId(job_id)})
    file_name = job_data["file_name"]
    if "report_id" in job_data.keys():
        report = db.get_file(job_data["report_id"])
        report_data = json.loads(report)
        mitm_url = report_data["mitmdump_url"]
        exec_output = report_data["output"]
        req_headers = report_data["request_headers"]
        proc_list = report_data["proc_list"]
        parent_list = get_parent_list(proc_list, job_id)
        parent_table = ParentTable(parent_list)
        distinct_table = DistinctTable(get_distinct_list(job_id))
        all_procs_url = f"http://localhost:5000/all_procs/{job_id}"
        return render_template(
            "report.html",
            title=file_name,
            mitmdump_url=mitm_url,
            execution_output=exec_output,
            request_headers=req_headers,
            parent_table=parent_table,
            distinct_table=distinct_table,
            all_procs_url=all_procs_url,
        )
    else:
        return "No report available."


@app.route("/get_mitmdump/<string:job_id>")
def get_mitmdump(job_id):
    try:
        db = DatabaseConnection()
        # mitmdump_record = db.run_logs[job_id].find_one({"mitm_file_id": {"$exists": True}})
        mitmdump_record = db.esfriend_jobs.find_one({"_id": ObjectId(job_id)})
        mitmdump_file_id = mitmdump_record["mitm_file_id"]
        file_handle = db.get_file_for_download(mitmdump_file_id)
        return send_file(
            file_handle, as_attachment=True, download_name=f"{job_id}.mitmdump"
        )
    except Exception as err:
        return err


@app.route("/proc/<string:job_id>/<int:pid>")
def proc(job_id, pid):
    try:
        db = DatabaseConnection()
        pid_cursor = db.run_logs[job_id].find({"pid": pid}, {"_id": 0}).sort("_id", 1)
        pid_events = []
        for event in pid_cursor:
            pid_events.append(event)
        return jsonify(pid_events)
    except Exception as err:
        return f"Could not retrieve PID data: {err}"


@app.route("/events/<string:job_id>/<string:event_type>")
def events(job_id, event_type):
    db = DatabaseConnection()
    events = db.run_logs[job_id].find({"event": event_type}, {"_id": 0}).sort("_id", 1)
    event_list = []
    for event in events:
        event_list.append(event)
    return jsonify(event_list)


@app.route("/print_procs/<string:job_id>")
def print_procs(job_id):
    try:
        db = DatabaseConnection()
        job_data = db.esfriend_jobs.find_one({"_id": ObjectId(job_id)})
        if "report_id" in job_data.keys():
            report = db.get_file(job_data["report_id"])
            db.client.close()
            report_data = json.loads(report)
            proc_list = report_data["proc_list"]
            return jsonify(proc_list)
    except Exception as err:
        return f"error: {err}"


@app.route("/all_procs/<string:job_id>")
def all_procs(job_id):
    db = DatabaseConnection()
    unique_pids = db.run_logs[job_id].distinct("pid")
    print(len(unique_pids))
    pid_list = []
    for pid in unique_pids:
        proc_path = db.run_logs[job_id].find_one({"pid": pid, "proc_path": {"$exists": True}})
        if proc_path is not None and "proc_path" in proc_path:
            pid_list.append(PidData(pid, proc_path["proc_path"], job_id))
        elif proc_path is None:
            pid_list.append(PidData(pid, "no process path", job_id))
    print(len(pid_list))
    pid_table = PidTable(pid_list)
    return render_template(
        "processes.html",
        title="All processes:",
        pid_table=pid_table,
    )