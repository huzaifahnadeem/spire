import subprocess
import socket
import os
import re

testing_config_agent = True
disabled = False


def get_hostname():
    return os.getenv("MY_HOSTNAME", "")

def get_my_ip():
    hostname = get_hostname()
    return socket.gethostbyname(hostname)

def start_spines(config_file, port, ip):
    cmd = ["./spines", "-c", config_file, "-p", str(port), "-I", ip]
    subprocess.Popen(cmd, cwd="/app/spire/spines/daemon")

def start_plc():
    cmd = ["./openplc", "-m","502"]
    subprocess.Popen(cmd, cwd="/app/spire/plcs/pnnl_plc")

# def start_config_agent(num):
#     cmd = ["./config_agent", "-h", "goldenrod" + str(num)]
#     subprocess.Popen(cmd, cwd="/app/spire/prime/bin")

if __name__ == "__main__":
    
    hostname = get_hostname()
    ip = get_my_ip()

    match = re.match(r"(aster|goldenrod)(\d+)$", hostname)
    if not match:
        print(f"Unrecognized hostname format: {hostname}")
        exit(1)

    prefix = match.group(1)  # "aster" or "goldenrod"
    num = int(match.group(2))
    print(f"Matched prefix: {prefix}, number: {num}")
    
    # Determine which Spines config file to use
    if prefix == "aster":
        if 1 <= num <= 6:
            config_file = "spines_ctrl_site_1.conf"
        elif 7 <= num <= 12:
            config_file = "spines_ctrl_site_2.conf"
        elif 13 <= num <= 18:
            config_file = "spines_ctrl_site_3.conf"
        elif num == 19:
            config_file = "spines_ctrl_site_4.conf"
        elif num == 20:
            config_file = "spines_ctrl_site_5.conf"
        else:
            print(f"Invalid aster number: {num}")
            exit(1)
    elif prefix == "goldenrod":
        if 1 <= num <= 6:
            config_file = "spines_ctrl_site_mcc.conf"
        else:
            print(f"Invalid goldenrod number: {num}")
            exit(1)
    else:
        print(f"Unknown prefix: {prefix}")
        exit(1)
    
    start_spines(config_file, 8200, ip)

    if num == 19:
        start_plc()

    # Keep container alive
    os.execvp("/bin/bash", ["/bin/bash"])
