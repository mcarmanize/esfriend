"""
    Utility methods

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

import hashlib
import subprocess
import platform


def sha256sum(file_path):
    sha256 = hashlib.sha256()
    block_size = 0x1000
    with open(file_path, "rb") as f:
        chunk = f.read(block_size)
        while chunk:
            sha256.update(chunk)
            chunk = f.read(block_size)

        checksum = sha256.hexdigest()
        return checksum


def ping(host):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    return (
        subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        == 0
    )


"""
    add new methods, not related to event strings, above this comment
"""

def get_event_string(event):
    try:
        event_string = "{},{}".format(event["event_type_description"], event["process_path"])
        event_dict = {
            "access": access_string,
            "authentication": authentication_string,
            "chdir": chdir_string,
            "clone": clone_string,
            "close": close_string,
            "create": create_string,
            "dup": dup_string,
            "exec": exec_string,
            "extattr": extattr_string,
            "exit": exit_string,
            "fcntl": fcntl_string,
            "fork": fork_string,
            "fsgetpath": fsgetpath_string,
            "get_task": get_task_string,
            "get_task_name": get_task_name_string,
            "get_task_read": get_task_read_string,
            "getattrlist": getattrlist_string,
            "getextattr": getextattr_string,
            "iokit_open": iokit_open_string,
            "listextattr": listextattr_string,
            "lookup": lookup_string,
            "mmap": mmap_string,
            "mount": mount_string,
            "mprotect": mprotect_string,
            "open": open_string,
            "proc_check": proc_check_string,
            "proc_suspend_resume": proc_suspend_resume_string,
            "readdir": readdir_string,
            "readlink": readlink_string,
            "rename": rename_string,
            "searchfs": searchfs_string,
            "setattrlist": setattrlist_string,
            "setegid": setegid_string,
            "seteuid": seteuid_string,
            "setextattr": setextattr_string,
            "setflags": setflags_string,
            "setgid": setgid_string,
            "setmode": setmode_string,
            "setowner": setowner_string,
            "setuid": setuid_string,
            "signal": signal_string,
            "stat": stat_string,
            "truncate": truncate_string,
            "uipc_bind": uipc_bind_string,
            "uipc_connect": uipc_connect_string,
            "unlink": unlink_string,
            "unmount": unmount_string,
            "utimes": utimes_string,
            "write": write_string,
        }
        event_string = event_dict[event["event_type_description"]](event_string, event)
        return event_string
    except Exception as err:
        print(f"{err}\n{event}\n")
        return ""

"""
    each event has a function to process contents
    please add in alphabetical order
"""

def access_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["access"]["target"]["path"],
        event["event"]["access"]["mode"]
    )
    return event_string

def authentication_string(event_string, event):
    event_string += ",{},{},{},{},{},{},{}".format(
        event["event"]["authentication"]["data"]["od"]["instigator"]["executable"]["path"],
        event["event"]["authentication"]["success"],
        event["event"]["authentication"]["type"],
        event["event"]["authentication"]["data"]["od"]["node_name"],
        event["event"]["authentication"]["data"]["od"]["record_type"],
        event["event"]["authentication"]["data"]["od"]["record_name"],
        event["event"]["authentication"]["data"]["od"]["db_path"],
    )
    return event_string

def chdir_string(event_string, event):
    event_string += ",{}".format(event["event"]["chdir"]["target"]["path"])
    return event_string

def clone_string(event_string, event):
    if "target" in event["event"]["clone"]:
        event_string += ",{},{},{}".format(
            event["event"]["clone"]["source"]["path"],
            event["event"]["clone"]["target"]["path"],
            event["event"]["clone"]["target_name"]
        )
    elif "target_dir" in event["event"]["clone"]:
        event_string += ",{},{},{}".format(
            event["event"]["clone"]["source"]["path"],
            event["event"]["clone"]["target_dir"]["path"],
            event["event"]["clone"]["target_name"]
        )
    return event_string

def close_string(event_string, event):
    event_string += ",{},{},{}".format(
        event["event"]["close"]["target"]["path"],
        event["event"]["close"]["modified"],
        event["event"]["close"]["was_mapped_writable"]
    )
    return event_string

def create_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["create"]["destination"]["existing_file"]["path"],
        event["event"]["create"]["acl"]
    )
    return event_string

def dup_string(event_string, event):
    event_string += ",{}".format(event["event"]["dup"]["target"]["path"])
    return event_string
    
def exec_string(event_string, event):
    event_string += ",{},{},{},{}".format(
        event["pcommand"],
        event["rcommand"],
        event["command"],
        event["event"]["exec"]["script"]

    )
    return event_string

def exit_string(event_string, event):
    event_string += ",{}".format(event["event"]["exit"]["stat"])
    return event_string

def extattr_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["extattr"]["target"]["path"],
        event["event"]["extattr"]["flags"]
    )
    return event_string

def fcntl_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["fcntl"]["target"]["path"],
        event["event"]["fcntl"]["cmd"]
    )
    return event_string

def fork_string(event_string, event):
    event_string += ",{}".format(event["event"]["fork"]["child"]["executable"]["path"])
    return event_string

def fsgetpath_string(event_string, event):
    event_string += ",{}".format(event["event"]["fsgetpath"]["target"]["path"])
    return event_string

def get_task_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["get_task"]["target"]["executable"]["path"],
        event["event"]["get_task"]["type"]
    )
    return event_string    

def get_task_name_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["get_task_name"]["target"]["executable"]["path"],
        event["event"]["get_task_name"]["type"]
    )
    return event_string

def get_task_read_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["get_task_read"]["target"]["executable"]["path"],
        event["event"]["get_task_read"]["type"]
    )
    return event_string

def getattrlist_string(event_string, event):
    event_string += ",{}".format(event["event"]["getattrlist"]["target"]["path"])
    return event_string
        
def getextattr_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["getextattr"]["target"]["path"],
        event["event"]["getextattr"]["extattr"]
    )
    return event_string

def iokit_open_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["iokit_open"]["user_client_class"],
        event["event"]["iokit_open"]["user_client_type"]
    )
    return event_string

def listextattr_string(event_string, event):
    event_string += ",{}".format(event["event"]["listextattr"]["target"]["path"])
    return event_string

def lookup_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["lookup"]["source_dir"]["path"],
        event["event"]["lookup"]["relative_target"]
    )
    return event_string

def mmap_string(event_string, event):
    event_string += ",{},{},{},{}".format(
        event["event"]["mmap"]["source"]["path"],
        event["event"]["mmap"]["flags"],
        event["event"]["mmap"]["protection"],
        event["event"]["mmap"]["max_protection"],
    )
    return event_string

def mount_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["mount"]["stat_fs"]["f_mntfromname"],
        event["event"]["mount"]["stat_fs"]["f_mntonname"]
    )
    return event_string

def mprotect_string(event_string, event):
    event_string += ",{}".format(event["event"]["mprotect"]["protection"])
    return event_string

def open_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["open"]["file"]["path"],
        event["event"]['open']["fflag"]
    )
    return event_string

def proc_check_string(event_string, event):
    if event["event"]["proc_check"]["target"] is not None:
        event_string += ",{},{},{}".format(
            event["event"]["proc_check"]["target"]["executable"]["path"],
            event["event"]["proc_check"]["type"],
            event["event"]["proc_check"]["flavor"]
        )
    else:
        event_string += ",{},{}".format(
            event["event"]["proc_check"]["type"],
            event["event"]["proc_check"]["flavor"]
        )
    return event_string

def proc_suspend_resume_string(event_string, event):
    event_string += ",{}".format(event["event"]["proc_suspend_resume"]["target"]["executable"]["path"])
    return event_string

def readdir_string(event_string, event):
    event_string += ",{}".format(event["event"]["readdir"]["target"]["path"])
    return event_string

def readlink_string(event_string, event):
    event_string += ",{}".format(event["event"]["readlink"]["source"]["path"])
    return event_string

def rename_string(event_string, event):
    if "new_path" in event["event"]["rename"]:
        event_string += ",{},{},{},{}".format(
            event["event"]["rename"]["source"]["path"],
            event["event"]["rename"]["new_path"]["dir"],
            event["event"]["rename"]["new_path"]["filename"],
            event["event"]["rename"]["destination_type"]
        )
    elif "existing_file" in event["event"]["rename"]:
        event_string += ",{},{},{},{}".format(
            event["event"]["rename"]["source"]["path"],
            event["event"]["rename"]["existing_file"]["path"],
            event["event"]["rename"]["destination_type"]
        )
    return event_string

def searchfs_string(event_string, event):
    event_string += ",{}".format(event["event"]["searchfs"]["target"]["path"])
    return event_string

def setattrlist_string(event_string, event):
    event_string += ",{},{},{},{},{},{}".format(
        event["event"]["setattrlist"]["target"]["path"],
        event["event"]["setattrlist"]["attrlist"]["bitmapcount"],
        event["event"]["setattrlist"]["attrlist"]["commonattr"],
        event["event"]["setattrlist"]["attrlist"]["dirattr"],
        event["event"]["setattrlist"]["attrlist"]["fileattr"],
        event["event"]["setattrlist"]["attrlist"]["forkattr"]
    )
    return event_string

def setegid_string(event_string, event):
    event_string += ",{}".format(event["event"]["setegid"]["egid"])
    return event_string

def seteuid_string(event_string, event):
    event_string += ",{}".format(event["event"]["seteuid"]["euid"])
    return event_string

def setextattr_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["setextattr"]["target"]["path"],
        event["event"]["setextattr"]["extattr"]
    )
    return event_string

def setflags_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["setflags"]["target"]["path"],
        event["event"]["setflags"]["extattr"]
    )
    return event_string

def setgid_string(event_string, event):
    event_string += ",{}".format(event["event"]["setgid"]["gid"])
    return event_string

def setmode_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["setmode"]["target"]["path"],
        event["event"]["setmode"]["mode"]
    )
    return event_string

def setowner_string(event_string, event):
    event_string += ",{},{},{}".format(
        event["event"]["setowner"]["target"]["path"],
        event["event"]["setowner"]["uid"],
        event["event"]["setowner"]["gid"]
    )
    return event_string

def setuid_string(event_string, event):
    event_string += ",{}".format(event["event"]["setuid"]["uid"])
    return event_string

def signal_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["signal"]["sig"],
        event["event"]["signal"]["target"]["executable"]["path"]
    )
    return event_string

def stat_string(event_string, event):
    event_string += ",{}".format(event["event"]["stat"]["target"]["path"])
    return event_string

def truncate_string(event_string, event):
    event_string += ",{}".format(event["event"]["truncate"]["target"]["path"])
    return event_string

def uipc_bind_string(event_string, event):
    event_string += ",{},{},{}".format(
        event["event"]["uipc_bind"]["dir"]["path"],
        event["event"]["uipc_bind"]["filename"],
        event["event"]["uipc_bind"]["mode"]
    )
    return event_string

def uipc_connect_string(event_string, event):
    event_string += ",{},{},{},{}".format(
        event["event"]["uipc_connect"]["file"]["path"],
        event["event"]["uipc_connect"]["domain"],
        event["event"]["uipc_connect"]["protocol"],
        event["event"]["uipc_connect"]["type"]
    )
    return event_string

def unlink_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["unlink"]["target"]["path"],
        event["event"]["unlink"]["parent_dir"]["path"]
    )
    return event_string

def unmount_string(event_string, event):
    event_string += ",{},{}".format(
        event["event"]["unmount"]["stat_fs"]["f_mntfromname"],
        event["event"]["unmount"]["stat_fs"]["f_mntonname"]
    )
    return event_string

def utimes_string(event_string, event):
    event_string += ",{}".format(event["event"]["utimes"]["target"]["path"])
    return event_string

def write_string(event_string, event):
    event_string += ",{}".format(event["event"]["write"]["target"]["path"])
    return event_string