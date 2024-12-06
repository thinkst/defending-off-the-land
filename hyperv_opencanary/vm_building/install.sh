INSTALL_BASE_IP=1.1.1.1


cd /etc/systemd/system
wget http://${INSTALL_BASE_IP}:8000/opencanary-watcher.path
wget http://${INSTALL_BASE_IP}:8000/opencanary-watcher.service
wget http://${INSTALL_BASE_IP}:8000/opencanary.service
systemctl enable opencanary-watcher.path
systemctl enable opencanary-watcher.service
systemctl enable opencanary.service
systemctl start opencanary-watcher.path
cd /root
wget http://${INSTALL_BASE_IP}:8000/oc_manager.py
systemctl start opencanary.service

useradd -m canary
apt install python3-virtualenv iptables sudo
virtualenv /home/canary/env
. /home/canary/env/bin/activate
pip install opencanary
opencanaryd --copyconfig
touch /var/tmp/opencanary.log