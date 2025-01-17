# NTPddos
A type of ddos exploiting the ntp servers through monlist request and ip forge

use python 3.9 to run

setup:
1. git clone
2. pip install -r requirements.txt
3. install npcap packet (requirement for scapy lib, from https://npcap.com/#download)

to exe: pyinstaller -F -w -i icon.ico attacker_with_ui.py

to scan available monlist NTP servers, you may use scanner.py
