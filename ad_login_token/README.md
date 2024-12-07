# AD Login monitor

Detect when threat actors use discovered fake credentials in your AD.

# How it works

On high-value locations within your AD environment, drops usernames and passwords in text files or other storage locations. The usernames _must_ be invalid (i.e. not legitimate users).

Then run the ad_login.ps1 script on an AD controller. It will setup a scheduled task to look for those fake usernames in your AD authentication logs.

NOTE: This is a PoC more than a production script. We suggest building in it, rather than using it directly as is. We have NOT tested it widely.

# Setup

1. Head to [Canarytokens.org](https://canarytokens.org) and create a new Web Bug Canarytoken. Keep the unique value handy.
2. Clone this repo, and copy `ad_login.ps1` to an AD controller.
3. Edit `ad_login.ps1`:
   1. Insert the Canarytoken value in the `$canarytoken` line
   2. Edit the `$tokenedUsernames` to hold a list of fake usernames that you've distributed around your network.
4. Run `ad_login.ps1` as an Administrator.