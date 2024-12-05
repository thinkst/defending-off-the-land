# Windows Registry monitor

## Quick-start

To run once, simply execute `.\reg-check.ps1`. If you want to setup a task that performs a check every 30 minutes, edit line 8 of the script
to set a Canarytoken web bug URL instead of `'none'`. Then run `.\reg-check.ps1 -Install`.

To remove, delete the task "RegistryMonitor" from the scheduled task list.

## Why

There are a number of living-off-the-land techniques that modify specific keys of the Registry. This tool monitors the ~80 keys that Elastic
maintains in their [detection rules repo](https://github.com/elastic/detection-rules). If they change, you'll get a pop-up notification, and
optionally a [Canarytokens.org](https://canarytokens.org/nest/) web bug can be triggered.
