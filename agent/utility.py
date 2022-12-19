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
import os
from database import DatabaseConnection
from agent_config import MONGO_CONNECTION_STRING, P7ZIP


def sha256sum(file_path):
    """get file checksum from file path"""
    try:
        sha256 = hashlib.sha256()
        block_size = 0x1000
        with open(file_path, "rb") as f:
            chunk = f.read(block_size)
            while chunk:
                sha256.update(chunk)
                chunk = f.read(block_size)

            checksum = sha256.hexdigest()
            return checksum
    except Exception as err:
        return err


def p7z(file_path):
    """use p7zip to extract a file by file path"""
    command = [P7ZIP, "x", file_path, "-o/tmp"]
    p7z_process = subprocess.Popen(command, stdout=subprocess.PIPE)
    p7z_process.communicate()
    result = p7z_process.returncode == 0
    print("7z returncode: {}".format(p7z_process.returncode))
    print("7z result: {}".format(result))
    return result


def find_app_in_tmp():
    """walk tmp to find .app package"""
    for root, dirs, _ in os.walk("/tmp"):
        for directory in dirs:
            if "__MACOSX" in directory:
                pass
            else:
                if directory.endswith(".app"):
                    return os.path.join(root, directory)


def add_x_flag(file_path):
    """add execute flag to file"""
    chmod_cmd = ["/bin/chmod", "+x", file_path]
    result = (
        subprocess.call(chmod_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        == 0
    )
    return result

def get_pid_command(pid):
    get_ps = subprocess.Popen(
        ["ps", "-p", str(pid), "-o", "command="],
        stdout=subprocess.PIPE,
    )
    command = get_ps.stdout.read().decode("utf-8").rstrip(" \n")
    return command


"""
    we gather a list of supported events from eslogger
    this is a list of event types that should be excluded, if desired
    leaving full list to allow configuration (may need occasional updating)
    commented events are collected, uncommented events are ignored
    current configuration is intended to ignore most file events/process events
    since these events are handled by procmon and filemon modules

    limiting the amount of events because we may need to multiprocess this list
    since using eslogger for all event at once seems to slow things down too much
"""
EXCLUDED_EVENTS = [
    "",
    "access",
    # "authentication",
    # "btm_launch_item_add",
    # "btm_launch_item_remove",
    "chdir",
    "chroot",
    "clone",
    "close", # filemon event
    "copyfile",
    "create", # filemon event
    # "cs_invalidated",
    # "deleteextattr",
    "dup",
    "exchangedata",
    "exec", # procmon event
    "exit", # procmon event
    "fcntl",
    # "file_provider_materialize",
    # "file_provider_update",
    "fork", # procmon event
    "fsgetpath",
    "get_task",
    "get_task_inspect",
    "get_task_name",
    "get_task_read",
    "getattrlist",
    "getextattr",
    # "iokit_open",
    # "kextload",
    # "kextunload",
    "link",
    "listextattr",
    # "login_login",
    # "login_logout",
    "lookup",
    "lw_session_lock",
    "lw_session_login",
    "lw_session_logout",
    "lw_session_unlock",
    "mmap",
    # "mount",
    "mprotect",
    "open", # filemon event
    # "openssh_login",
    # "openssh_logout",
    "proc_check",
    "proc_suspend_resume",
    "pty_close",
    "pty_grant",
    "readdir",
    "readlink",
    "remote_thread_create",
    "remount",
    "rename", # filemon event
    # "screensharing_attach",
    # "screensharing_detach",
    "searchfs",
    "setacl",
    "setattrlist",
    "setegid",
    "seteuid",
    # "setextattr",
    # "setflags",
    # "setgid",
    # "setmode",
    # "setowner",
    "setregid",
    "setreuid",
    "settime",
    # "setuid",
    "signal", # procmon event
    "stat",
    "trace",
    "truncate",
    # "uipc_bind",
    # "uipc_connect",
    "unlink",
    # "unmount",
    "utimes",
    "write", # filemon event
    # "xp_malware_detected",
    # "xp_malware_remediated"
]
