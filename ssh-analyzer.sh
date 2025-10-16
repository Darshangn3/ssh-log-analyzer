#!/bin/bash

read -p "Enter path to combined log file: " LOGFILE
[[ ! -r "$LOGFILE" ]] && { echo "File missing or unreadable"; exit 1; }

THRESHOLD=2
echo "Analyzing SSH login attempts..."

awk -v thresh="$THRESHOLD" '
/sshd.*(Accepted|Failed) password/ {
    status = /Accepted/ ? "Accepted" : "Failed";
    timestamp = $1" "$2" "$3;
    ip = cport = "";
    for(i=1;i<=NF;i++) {
        if($i=="from") ip=$(i+1);
        if($i=="port") cport=$(i+1);
    }
    if(ip && cport) auth_status[timestamp "|" ip "|" cport] = status;
}
/NETLOG: SRC=/ {
    timestamp = $1" "$2" "$3;
    src_ip = src_port = dst_ip = dst_port = "";
    for(i=1;i<=NF;i++) {
        if($i ~ /^SRC=/) split($i,a,"="); src_ip = a[2];
        if($i ~ /^SPT=/) split($i,a,"="); src_port = a[2];
        if($i ~ /^DST=/) split($i,a,"="); dst_ip = a[2];
        if($i ~ /^DPT=/) split($i,a,"="); dst_port = a[2];
    }
    if(src_ip && src_port) {
        key = timestamp "|" src_ip "|" src_port;
        netlog_dst_ip[key] = dst_ip;
        netlog_dst_port[key] = dst_port;
    }
}
END {
    print "=== Successful SSH Logins ===";
    for(k in auth_status) if(auth_status[k]=="Accepted") {
        split(k,a,"|");
        printf "%-15s %-8s %-15s %-8s %s\n", a[2], a[3], netlog_dst_ip[k], netlog_dst_port[k], auth_status[k];
    }
    print "\n=== Suspicious Failed SSH Attempts (threshold > " thresh ") ===";
    for(k in auth_status) if(auth_status[k]=="Failed") {
        split(k,a,"|");
        count[a[2]","a[3]","netlog_dst_port[k]]++;
    }
    for(c in count) if(count[c] > thresh) {
        split(c,a,",");
        printf "%-15s %-8s %-8s %d\n", a[1], a[2], a[3], count[c];
    }
}
' "$LOGFILE"

echo "Analysis complete."

