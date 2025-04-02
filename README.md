import os
import re

def get_user_auth_times(user_id):
    """
    Returns a list of the date and time of logins for user user_id from log/auth.log.x
    """
    auth_times = []
    log_dir = 'log'
    pattern = re.compile(r'^(.*?\d{2}:\d{2}:\d{2}).*session opened for user\s+{}'.format(re.escape(user_id)))

    for filename in os.listdir(log_dir):
        if filename.startswith('auth.log'):
            with open(os.path.join(log_dir, filename), 'r') as file:
                for line in file:
                    match = pattern.search(line)
                    if match:
                        auth_times.append(match.group(1))
    return auth_times

def get_invalid_logins():
    """
    Returns a dictionary mapping invalid user ids to # of failed logins on log/auth.log.x
    """
    invalid_logins = {}
    log_dir = 'log'
    pattern = re.compile(r'Invalid user (\S+) from')

    for filename in os.listdir(log_dir):
        if filename.startswith('auth.log'):
            with open(os.path.join(log_dir, filename), 'r') as file:
                for line in file:
                    match = pattern.search(line)
                    if match:
                        user = match.group(1)
                        invalid_logins[user] = invalid_logins.get(user, 0) + 1
    return invalid_logins

def compare_invalid_IPs():
    """
    Returns a set of IPs that were both used for invalid logins and blocked by the firewall
    """
    auth_ips = set()
    fw_ips = set()
    log_dir = 'log'

    auth_pattern = re.compile(r'Invalid user \S+ from (\d+\.\d+\.\d+\.\d+)')
    fw_pattern = re.compile(r'\[UFW BLOCK\].*SRC=(\d+\.\d+\.\d+\.\d+)')

    for filename in os.listdir(log_dir):
        if filename.startswith('auth.log'):
            with open(os.path.join(log_dir, filename), 'r') as file:
                for line in file:
                    match = auth_pattern.search(line)
                    if match:
                        auth_ips.add(match.group(1))

    for filename in os.listdir(log_dir):
        if filename.startswith('ufw.log'):
            with open(os.path.join(log_dir, filename), 'r') as file:
                for line in file:
                    match = fw_pattern.search(line)
                    if match:
                        fw_ips.add(match.group(1))

    return auth_ips & fw_ips

if __name__ == "__main__":
    print(get_user_auth_times("tylermoore"))
    print(get_invalid_logins())
    print(compare_invalid_IPs())
