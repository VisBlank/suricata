#!/bin/bash
# iptables to test IPS mode of Suricata

while :
do
    case $1 in
        -a) # insert new rules
            sudo iptables -I INPUT -j NFQUEUE
            sudo iptables -I OUTPUT -j NFQUEUE
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
