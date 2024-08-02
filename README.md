# 3asyPr1vs

3asyPr1vs is a Python-based privilege escalation tool designed to identify potential vulnerabilities and misconfigurations in Linux systems. It helps in discovering weaknesses that can be leveraged to gain elevated privileges.

Features
Sudo Permissions: Checks for passwordless sudo permissions.
Sensitive File Permissions: Identifies world-writable and weak permissions on critical files like /etc/passwd.
SUID Files: Detects files with the SUID bit set.
PATH Check: Ensures the current directory (.) is not in the PATH.
Cron Jobs: Finds world-writable cron job scripts.
NFS Shares: Detects shares with the no_root_squash option.
Installed Packages: Checks for known vulnerable versions.
Sudo Version: Identifies vulnerable sudo versions.
Insecure Sudoers Entries: Searches for insecure entries in /etc/sudoers.
Password Policies: Checks for weak policies.
Empty Passwords: Identifies users with empty passwords.
Shared Library Injection: Detects potential issues.
Locally Stored Credentials: Scans for files containing sensitive data.
Installation
Requirements
Python 3.x
colorama
Setup
Clone the repository:

sh
Копировать код
git clone https://github.com/username/3asyPr1vs.git
cd 3asyPr1vs
Install dependencies:

sh
Копировать код
pip install -r requirements.txt
Usage
Run the tool with elevated permissions:

sh
Копировать код
sudo python3 3asyPr1vs.py
License
This project is licensed under the MIT License. See the LICENSE file for details.

Author
Ram1z - Telegram
