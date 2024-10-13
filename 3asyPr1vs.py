#!/usr/bin/env python3

import os
import subprocess
import re
from colorama import Fore, Style

def print_banner():
    banner = f"""
{Fore.RED}
 .----.                   .---.      ,-.            
`--  ;                   : .; :   .'  :            
 .' '  .--.   .--. .-..-.:  _.'.--.`: :.-..-. .--. 
 _`,`.' .; ; `._-.': :; :: :   : ..': :: `; :`._-.'
`.__.'`.__,_;`.__.'`._. ;:_;   :_;  :_;`.__.'`.__.'
                    .-. :                          
                    `._.'                          
{Style.RESET_ALL}
Coded by R1chardAlmeyda
Telegram: t.me/RichardAlmeyda
"""
    print(banner)

def run_command(command):
    return subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()

def check_sudo_permissions():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for sudo permissions without password...")
    result = run_command('sudo -ln')
    if "NOPASSWD" in result:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} User has sudo permissions without password!")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No sudo permissions without password found.")

def check_sensitive_world_writable_files():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for world-writable sensitive files...")
    sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
    for file in sensitive_files:
        result = run_command(f'ls -l {file}')
        if result and "w" in result:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} World-writable permissions on {file}: {result}")
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No world-writable permissions on {file}")

def check_suid_files():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for SUID files...")
    result = run_command('find / -perm -4000 -type f 2>/dev/null')
    if result:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} SUID files found:\n{result}")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No SUID files found.")

def check_weak_file_permissions():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for weak file permissions on sensitive files...")
    sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
    for file in sensitive_files:
        result = run_command(f'ls -l {file}')
        if result and "rw-rw-r--" in result:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Weak permissions on {file}: {result}")
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No weak permissions on {file}")

def check_path_variable():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking PATH variable for current directory inclusion...")
    path = run_command('echo $PATH')
    if "." in path:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Current directory found in PATH: {path}")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No current directory in PATH")

def check_cron_jobs():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for cron jobs with writable scripts...")
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]
    for directory in cron_dirs:
        result = run_command(f'find {directory} -type f -perm -0002 2>/dev/null')
        if result:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} World-writable cron jobs found in {directory}:\n{result}")
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No world-writable cron jobs in {directory}")

def check_nfs_shares():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for NFS shares with no_root_squash option...")
    result = run_command('showmount -e 2>/dev/null')
    if result and "no_root_squash" in result:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} NFS shares with no_root_squash found:\n{result}")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No NFS shares with no_root_squash found")

def check_installed_packages():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for potentially vulnerable installed packages...")
    vulnerable_packages = {
        "sudo": "sudo --version | grep '1.8'",
        "docker": "docker --version | grep '18.09'",
        "mysql": "mysql --version | grep '5.7'"
    }
    for package, check_cmd in vulnerable_packages.items():
        result = run_command(check_cmd)
        if result:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Potentially vulnerable package {package} found:\n{result}")
        else:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} No potentially vulnerable package {package} found")

def check_sudo_version():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking sudo version for vulnerabilities...")
    sudo_version = run_command('sudo -V | grep "Sudo version"')
    if "1.8" in sudo_version or "1.9" in sudo_version:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Vulnerable sudo version found: {sudo_version}")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No vulnerable sudo version found")

def check_sudoers_insecure_entries():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking /etc/sudoers for insecure entries...")
    result = run_command('grep -E "ALL\s*=\s*\(ALL\)\s*NOPASSWD:\s*ALL" /etc/sudoers')
    if result:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Insecure sudoers entry found:\n{result}")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No insecure sudoers entries found")

def check_password_policies():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for weak password policies...")
    result = run_command('cat /etc/login.defs | grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE"')
    if result:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Weak password policies found:\n{result}")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No weak password policies found")

def check_users_with_empty_passwords():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for users with empty passwords...")
    result = run_command('cat /etc/shadow | awk -F: \'($2 == "") {print $1}\'')
    if result:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Users with empty passwords found:\n{result}")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No users with empty passwords found")

def check_shared_library_injection():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for potential shared library injection...")
    result = run_command('ldd $(which python3) 2>/dev/null')
    if "not found" in result:
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Potential shared library injection found.")
    else:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} No shared library injection issues found.")

def check_locally_stored_credentials():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for locally stored credentials...")
    directories = ["/var/www/html", "/root", "/etc"]
    sensitive_keywords = ["password", "passwd", "secret"]

    for directory in directories:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    # Attempt to open the file and check its contents
                    with open(file_path, 'r', errors='ignore') as f:
                        contents = f.read()
                        if any(keyword in contents.lower() for keyword in sensitive_keywords):
                            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Potential sensitive data found in {file_path}")
                            break  # Stop checking this file if sensitive data is found
                except (PermissionError, FileNotFoundError, IsADirectoryError, OSError) as e:
                    # Handle specific exceptions and continue
                    print(f"{Fore.RED}[-]{Style.RESET_ALL} Could not read {file_path}: {e}")
                    continue

                    
def check_misconfigured_file_permissions():
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Checking for misconfigured file permissions...")
    directories = ["/home", "/etc", "/var"]
    for directory in directories:
        result = run_command(f'find {directory} -type f -perm -0002 2>/dev/null')
        if result:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Misconfigured file permissions found in {directory}:\n{result}")
        else:
             print(f"{Fore.RED}[-]{Style.RESET_ALL} No misconfigured file permissions found in {directory}")

def main():
    print_banner()

    check_sudo_permissions()
    check_sensitive_world_writable_files()
    check_suid_files()
    check_weak_file_permissions()
    check_path_variable()
    check_cron_jobs()
    check_nfs_shares()
    check_installed_packages()
    check_sudo_version()
    check_sudoers_insecure_entries()
    check_password_policies()
    check_users_with_empty_passwords()
    check_shared_library_injection()
    check_locally_stored_credentials()
    check_misconfigured_file_permissions()

if __name__ == "__main__":
    main()
