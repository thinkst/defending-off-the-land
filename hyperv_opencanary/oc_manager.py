import base64
import json
import os
import signal
import subprocess
import sys
import time

KVP_SETTINGS_PATH="/var/lib/hyperv/.kvp_pool_0"
KVP_ALERT_PATH="/var/lib/hyperv/.kvp_pool_1"
MAX_KEY_SIZE=512
MAX_VAL_SIZE=2048
SETTINGS_FILE='/etc/opencanaryd/opencanary.conf'
LOG_FILE="/var/tmp/opencanary.log"
POWERSHELL_POLL_INTERVALL=5 # The sleep timeout in the Windows PowerShell poll loop

KEY_COUNTER="opencanary-alerts"
KEY_PREFIX="opencanary-alert-"

LOG_BASE_BOOT = 1000
LOG_BASE_MSG = 1001
LOG_BASE_DEBUG = 1002
LOG_BASE_ERROR = 1003
LOG_BASE_PING = 1004
LOG_BASE_CONFIG_SAVE = 1005
LOG_BASE_EXAMPLE = 1006
LOG_FTP_LOGIN_ATTEMPT = 2000
LOG_FTP_AUTH_ATTEMPT_INITIATED = 2001
LOG_HTTP_GET = 3000
LOG_HTTP_POST_LOGIN_ATTEMPT = 3001
LOG_HTTP_UNIMPLEMENTED_METHOD = 3002
LOG_HTTP_REDIRECT = 3003
LOG_SSH_NEW_CONNECTION = 4000
LOG_SSH_REMOTE_VERSION_SENT = 4001
LOG_SSH_LOGIN_ATTEMPT = 4002
LOG_SMB_FILE_OPEN = 5000
LOG_PORT_SYN = 5001
LOG_PORT_NMAPOS = 5002
LOG_PORT_NMAPNULL = 5003
LOG_PORT_NMAPXMAS = 5004
LOG_PORT_NMAPFIN = 5005
LOG_TELNET_LOGIN_ATTEMPT = 6001
LOG_TELNET_CONNECTION_MADE = 6002
LOG_HTTPPROXY_LOGIN_ATTEMPT = 7001
LOG_MYSQL_LOGIN_ATTEMPT = 8001
LOG_MSSQL_LOGIN_SQLAUTH = 9001
LOG_MSSQL_LOGIN_WINAUTH = 9002
LOG_MYSQL_CONNECTION_MADE = 9003
LOG_TFTP = 10001
LOG_NTP_MONLIST = 11001
LOG_VNC = 12001
LOG_SNMP_CMD = 13001
LOG_RDP = 14001
LOG_SIP_REQUEST = 15001
LOG_GIT_CLONE_REQUEST = 16001
LOG_REDIS_COMMAND = 17001
LOG_TCP_BANNER_CONNECTION_MADE = 18001
LOG_TCP_BANNER_KEEP_ALIVE_CONNECTION_MADE = 18002
LOG_TCP_BANNER_KEEP_ALIVE_SECRET_RECEIVED = 18003
LOG_TCP_BANNER_KEEP_ALIVE_DATA_RECEIVED = 18004
LOG_TCP_BANNER_DATA_RECEIVED = 18005
LOG_LLMNR_QUERY_RESPONSE = 19001
LOG_USER_0 = 99000
LOG_USER_1 = 99001
LOG_USER_2 = 99002
LOG_USER_3 = 99003
LOG_USER_4 = 99004
LOG_USER_5 = 99005
LOG_USER_6 = 99006
LOG_USER_7 = 99007
LOG_USER_8 = 99008
LOG_USER_9 = 99009

logtype_mapping = {
    LOG_TELNET_LOGIN_ATTEMPT:    { "header": "Telnet Login attempt by {alert_data[src_host]}", "body": "Username: {alert_data[logdata][USERNAME]}, Password: {alert_data[logdata][PASSWORD]}"},
    LOG_FTP_LOGIN_ATTEMPT:       { "header": "FTP Login attempt by {alert_data[src_host]}", "body": "Username: {alert_data[logdata][USERNAME]}, Password: {alert_data[logdata][PASSWORD]}"},
    LOG_HTTP_POST_LOGIN_ATTEMPT: { "header": "HTTP Login attempt by {alert_data[src_host]}", "body": "Username: {alert_data[logdata][USERNAME]}, Password: {alert_data[logdata][PASSWORD]}"},
    LOG_SSH_LOGIN_ATTEMPT:       { "header": "SSH Login attempt by {alert_data[src_host]}", "body": "Username: {alert_data[logdata][USERNAME]}, Password: {alert_data[logdata][PASSWORD]}"},
    LOG_SSH_REMOTE_VERSION_SENT: { "header": "SSH Handshake by {alert_data[src_host]}", "body": "They claim to be {alert_data[logdata][REMOTEVERSION]}"},
    LOG_PORT_NMAPOS:             { "header": "NMAP OS Scan by {alert_data[src_host]}", "body": "Someone is trying to fingerprint your machine"},
    LOG_REDIS_COMMAND:           { "header": "Redis command sent by {alert_data[src_host]}", "body": "Command: {alert_data[logdata][CMD]}, arguments: {alert_data[logdata][ARGS]}"},
    LOG_MYSQL_LOGIN_ATTEMPT:     { "header": "MySQL Login attempt by {alert_data[src_host]}", "body": "Username: {alert_data[logdata][USERNAME]}, Password: {alert_data[logdata][PASSWORD]}"},
    LOG_MSSQL_LOGIN_SQLAUTH:     { "header": "MSSQL Login attempt via SQLAuth by {alert_data[src_host]}", "body": "Username: {alert_data[logdata][UserName]}, Client Software: {alert_data[logdata][AppName]}, Client Hostname: {alert_data[logdata][HostName]}"},
    LOG_MSSQL_LOGIN_WINAUTH:     { "header": "MSSQL Login attempt via WinAuth by {alert_data[src_host]}", "body": "Username: {alert_data[logdata][USERNAME]}, Password: {alert_data[logdata][PASSWORD]}"},
    LOG_VNC:                     { "header": "VNC Login attempt by {alert_data[src_host]}", "body": "Password: {alert_data[logdata][PASSWORD]}"},
}

last_wipe = time.time()
def write_alert(counter, header, body):
    global last_wipe
    with open(KVP_ALERT_PATH, "r+b") as f:
        f.write(KEY_COUNTER.encode("utf8"))
        f.write(("\x00"*(MAX_KEY_SIZE-len(KEY_COUNTER))).encode("utf8"))
        f.write(str(counter).encode("utf8"))
        f.write(("\x00"*(MAX_VAL_SIZE-len(str(counter)))).encode("utf8"))

        if time.time() - last_wipe > POWERSHELL_POLL_INTERVALL + 2: # The extra 2 seconds is a fudge factor to allow for slight delays
            last_wipe = time.time()
            f.truncate()
        else:
            f.seek(0, 2)

        _key = f"{KEY_PREFIX}{counter}".encode("utf8")
        raw_alert_data = json.dumps({"Header": header, "Body": body}).encode("utf8")
        f.write(_key)
        f.write(("\x00"*(MAX_KEY_SIZE-len(_key))).encode("utf8"))
        f.write(raw_alert_data)
        f.write(("\x00"*(MAX_VAL_SIZE-len(raw_alert_data))).encode("utf8"))

def process_alert(line):
    alert_data = json.loads(line)
    logtype = alert_data['logtype']
    if logtype not in logtype_mapping:
        return None, None
    
    header = logtype_mapping[logtype]["header"].format(alert_data=alert_data)
    body   = logtype_mapping[logtype]["body"].format(alert_data=alert_data)
    return header,body

def tail_log(file_path):
    with open(file_path, 'r') as file:
        # Move the file pointer to the end of the file
        file.seek(0, 2)
        counter = 0
        while True:
            # Read a new line if available
            line = file.readline()
            if not line:
                # If no new line, wait briefly and try again
                time.sleep(0.5)
                continue
            counter += 1
            header, body = process_alert(line)
            if header is not None and body is not None:
                write_alert(counter, header, body)

def get_kv_pairs():
    kv_pairs = {}
    with open(KVP_SETTINGS_PATH, 'r') as f:
        contents = f.read()

    while len(contents) > 0:
        key = contents[:MAX_KEY_SIZE]
        value = contents[MAX_KEY_SIZE:MAX_VAL_SIZE]
        contents = contents[(MAX_KEY_SIZE+MAX_VAL_SIZE):]
        key = key[:key.find('\x00')]
        value = value[:value.find('\x00')]
        kv_pairs[key] = value
    
    return kv_pairs

def configure_network(kv_pairs):
    network_info = kv_pairs['NetworkInfo'].split(',')
    ip_address = network_info[0]
    gateway = network_info[1]
    dns = network_info[2]
    if ip_address not in subprocess.run("/sbin/ip a show dev eth0", shell=True, capture_output=True).stdout.decode("utf8"):
        subprocess.run(f"/sbin/ip a add {ip_address} dev eth0", shell=True)
        subprocess.run(f"/sbin/ip route add 0.0.0.0/0 via {gateway}", shell=True)
        subprocess.run(f"echo 'nameserver {dns}' > /etc/resolv.conf", shell=True)

def read_oc_configuration(kv_pairs):
    incoming_settings = json.loads(base64.b64decode(kv_pairs['CanarySettings']))
    
    with open(SETTINGS_FILE, 'r') as f:
        current_settings = json.loads(f.read())

        
    for setting, value in incoming_settings.items():
        current_settings[setting] = value

    with open(SETTINGS_FILE, 'w') as f:
        f.write(json.dumps(current_settings))

def launch_oc():
    with open(KVP_ALERT_PATH, "w") as f:
        pass # wipe the file
    subprocess.run(". /home/canary/env/bin/activate; opencanaryd --start --uid=nobody --gid=nogroup", shell=True)

def exit_gracefully(signum, frame):
    with open("/home/canary/env/bin/opencanaryd.pid", 'r') as f:
        pid = int(f.read().strip())
    os.kill(pid, signal.SIGKILL)
    sys.exit(0)

kv_pairs = get_kv_pairs()
if len(kv_pairs) == 0:
    print("No config pairs were seen from the Hyper-V host, has the VM been launched through the OpenCanary.ps1 script?", file=sys.stderr)
    print("I am simply doing nothing right now...", file=sys.stderr)
    # The systemd unit will keep restarting if we bail now, so just... do nothing
    while True:
        time.sleep(10000000)

configure_network(kv_pairs)
read_oc_configuration(kv_pairs)
launch_oc()
signal.signal(signal.SIGINT, exit_gracefully)
tail_log(LOG_FILE)
