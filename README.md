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
