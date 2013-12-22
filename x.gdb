file ./src/suricata
b main
b SCInstanceInit
r -c suricata.yaml -i wlan0
set print pretty
