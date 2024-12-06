# Hyper-V OpenCanary

Run a honeypot on your Windows machine in Hyper-V. Alerts will show up both visually (as toasts), and in your event log.

# Installation

1. Run Powershell as Administrator
2. Clone this repo
3. `cd hyperv_opencanary`
4. `wget -OutFile opencanary.zip https://opencanary-hyperv-image.s3.eu-west-1.amazonaws.com/opencanary.zip; Expand-Archive opencanary.zip -DestinationPath .\`
   
# Edit the configuration

Open `OpenCanary.ps1`, and edit two sections:
1. `$canarySettings` holds the OpenCanary settings, and will be passed into the VM for OpenCanary to run. The settings are documented [here](https://opencanary.readthedocs.io/en/latest/starting/configuration.html).
2. The `$portMapping` holds the NAT port mapping, from the Windows' public IP port to the internal OpenCanary port. By default, OpenCanary's services will listen on their expected ports (e.g. if you enable the SSH service, it listens on port 22.) For every service you enabled in `$canarySettings`, you will need to map an external Windows port.

# Run the VM setup and monitoring script

After the config and been edited and the VM downloaded and unpacked, simply run:
```
C:\> .\OpenCanary.ps1
```

This will import the VM (if necessary), launch it, configure the network, and set up all the port NATing details. It will also monitor for OpenCanary alerts, and will show alerts as they come in. If the script isn't running, no alerts will be seen.

At any time hit Ctrl-C to kill the script. Note that this won't stop the VM or remove the port mappings in place, 

The script is re-entrant. If the VM is running, simply re-run the script and it'll start monitoring for alerts again.

# Events

1. Open your Event Log
2. Click "Windows Logs" > "Application"
3. Events show up with Source "OpenCanary", event ID "1"

# Shutdown

Manually stop the VM:
```
C:\> Stop-VM -Name OpenCanary
```