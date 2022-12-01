"""
    Configure physical machines

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
from database import DatabaseConnection
from config import MACHINES
from utility import ping


class Machine:
    def __init__(self):
        self.configure_machines()

    def configure_machines(self):
        db = DatabaseConnection()
        clean_result = db.esfriend_machines.delete_many({"machine_type": "physical"})
        self.machines = {}
        for machine in MACHINES.keys():
            ping_result = ping(MACHINES[machine]["ipaddress"])
            if ping_result:
                # machine is on and connected, that's all we know about it
                self.machines[machine] = MACHINES[machine]
                # self.machine_list.append(machine)
                machine_data = {
                    "machine_type": "physical",
                    "machine_name": machine,
                    "ipaddress": MACHINES[machine]["ipaddress"],
                    "assigned_job": None,
                }
                result = db.esfriend_machines.insert_one(machine_data)
                print(f"Added {machine} to esfriend")
            else:
                raise Exception(
                    "Ping Failed. Machine is either off or incorrectly configured."
                )
        db.client.close()


if __name__ == "__main__":
    Machine()
