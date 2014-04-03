#!/bin/bash
# iptables to test IPS mode of Suricata

while :
do
    case $1 in
        -a) # insert new rules
            #sudo iptables -I INPUT -j NFQUEUE
            #sudo iptables -I OUTPUT -j NFQUEUE
			# TNS11g test iptables
			#sudo iptables -A INPUT -i eth0 -p tcp -s 192.168.37.194 -j NFQUEUE
			#sudo iptables -A OUTPUT -p tcp --dport 1521 -s 192.168.37.193 -j NFQUEUE

			# Mysql test iptables
			sudo iptables -A INPUT -i eth0 -p tcp -s 192.168.37.184 -j NFQUEUE
			sudo iptables -A OUTPUT -p tcp --dport 3306 -s 192.168.37.193 -j NFQUEUE
            break
            ;;
        -c) # clean rules
            sudo iptables -F
            sudo iptables -X
            sudo iptables -P INPUT ACCEPT
            sudo iptables -P OUTPUT ACCEPT
            break
            ;;
        -s) # show
            sudo iptables -vnL
            break
            ;;
        *)
            echo "warn: unknown options (ignored): $1" >&2
            break
            ;;
    esac
done
