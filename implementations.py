import json
from enum import Enum

IMPLEMENTATIONS = {}


class Role(Enum):
    BOTH = "both"
    SERVER = "server"
    CLIENT = "client"
    ATTACKER = "attacker"

with open("implementations.json", "r") as f:
    data = json.load(f)
    for name, val in data.items():
        IMPLEMENTATIONS[name] = {"image": val["image"], "url": val["url"]}
        role = val["role"]
        if role == "server":
            IMPLEMENTATIONS[name]["role"] = Role.SERVER
        elif role == "client":
            IMPLEMENTATIONS[name]["role"] = Role.CLIENT
        elif role == "both":
            IMPLEMENTATIONS[name]["role"] = Role.BOTH
        elif role == "attacker":
            IMPLEMENTATIONS[name]["role"] = Role.ATTACKER
        else:
            raise Exception("unknown role: " + role)