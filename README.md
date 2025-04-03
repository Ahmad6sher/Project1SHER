# Project 1 — Network Log Analysis

This project implements three Python functions to analyze authentication and firewall logs.

## Functions

get_user_auth_times(user_id)  
Returns a list of the date and time of logins for a given user from log/auth.log.x files.

get_invalid_logins()  
Returns a dictionary mapping invalid user IDs to the number of failed login attempts from log/auth.log.x files.

compare_invalid_IPs()  
Returns a set of IP addresses that are used for both invalid logins and blocked by the firewall using log/auth.log and log/ufw.log files.

## How to Run

1. Place all your log files inside a folder named log/
2. Run the script using:

python3 main.py

## Example Output

['Feb 21 13:29:56', 'Feb 21 13:36:38', 'Feb 21 13:33:56']

{'admin': 17, 'oracle': 21, 'test': 21, ...}

{'141.98.11.23', '64.62.197.182', '45.125.65.126', ...}

Code:

import os
import re

def get_user_auth_times(user_id):
    times = []
    for file in os.listdir("log"):
        if file.startswith("auth.log"):
            with open(os.path.join("log", file), "r") as f:
                for line in f:
                    if f"session opened for user {user_id}" in line:
                        match = re.match(r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})", line)
                        if match:
                            times.append(match.group(1))
    return times

def get_invalid_logins():
    users = {}
    pattern = re.compile(r"Invalid user (\S+) from")
    for file in os.listdir("log"):
        if file.startswith("auth.log"):
            with open(os.path.join("log", file), "r") as f:
                for line in f:
                    match = pattern.search(line)
                    if match:
                        user = match.group(1)
                        users[user] = users.get(user, 0) + 1
    return users

def compare_invalid_IPs():
    auth_ips = set()
    fw_ips = set()
    auth_pattern = re.compile(r"Invalid user \S+ from (\d+\.\d+\.\d+\.\d+)")
    fw_pattern = re.compile(r"\[UFW BLOCK\].*SRC=(\d+\.\d+\.\d+\.\d+)")
    for file in os.listdir("log"):
        path = os.path.join("log", file)
        if file.startswith("auth.log"):
            with open(path, "r") as f:
                for line in f:
                    match = auth_pattern.search(line)
                    if match:
                        auth_ips.add(match.group(1))
        elif file.startswith("ufw.log"):
            with open(path, "r") as f:
                for line in f:
                    match = fw_pattern.search(line)
                    if match:
                        fw_ips.add(match.group(1))
    return auth_ips & fw_ips

if __name__ == "__main__":
    print(get_user_auth_times("tylermoore"))
    print(get_invalid_logins())
    print(compare_invalid_IPs())

