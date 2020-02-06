#!/usr/bin/env bash

sudo nmap -sS -Pn -n -p 22 -T5 --min-hostgroup=2000 --max-rtt-timeout=500ms --min-rate=10000 --open -oG ssh22.txt 0.0.0.0/0
cat ssh22.txt | sed "/.*Up/d" | sed "s/Host: \([0-9.]*\) .*/\1/g" | sed '1d; $d; /.*Up/d; s/Host: \([0-9.]*\) .*/\1/g' > ./data/ssh22.txt

sudo nmap -sS -Pn -n -p 443 -T5 --min-hostgroup=2000 --max-rtt-timeout=500ms --min-rate=10000 --open -oG tls443.txt 0.0.0.0/0
cat tls443.txt | sed "/.*Up/d" | sed "s/Host: \([0-9.]*\) .*/\1/g" | sed '1d; $d; /.*Up/d; s/Host: \([0-9.]*\) .*/\1/g' > ./data/tls443.txt
