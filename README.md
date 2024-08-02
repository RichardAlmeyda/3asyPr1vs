# Introduction

![Screenshot 2024-08-02 160031](https://github.com/user-attachments/assets/3e8bf329-c624-4576-b878-e447862d99e3)

3asyPr1vs is a Python-based privilege escalation tool designed to identify potential vulnerabilities and misconfigurations in Linux systems. It helps in discovering weaknesses that can be leveraged to gain elevated privileges.

# Instalation

> git clone https://github.com/username/3asyPr1vs.git

> cd 3asyPr1vs



Install dependencies

> pip install -r requirements.txt

Make the script executable

> chmod +x 3asyPr1vs.py




# Usage
/List all the features

> python3 3asyPr1vs.py --list    or    ./3asyPr1vs.py --list


/Run the script

> python3 3asyPr1vs.py or ./3asyPr1vs.py


![image](https://github.com/user-attachments/assets/71f57218-e036-43a8-af83-1b8a5a4a476d)

# Features
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


-------------------------------------------------------------------------

License
This project is licensed under the MIT License. See the LICENSE file for details.

--------------------------------------------------------------------------
Author 
tg : t.me/root777777
