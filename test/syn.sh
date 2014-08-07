#!/bin/bash - 
#===============================================================================
#
#          FILE:  syn.sh
# 
#         USAGE:  ./syn.sh 
# 
#   DESCRIPTION:  anti-syn test script
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR: YOUR NAME (), 
#       COMPANY: 
#       CREATED: 04/01/2011 03:31:59 PM CST
#      REVISION:  ---
#===============================================================================

set -o nounset                              # Treat unset variables as an error

psecin=10
burin=30
psecfo=100
burfo=300
#-------------------------------------------------------------------------------
# 每秒 最多3个 syn 封包 进入 
#-------------------------------------------------------------------------------
op_add_rules () {
    iptables -N syn-flood-input
    iptables -A INPUT -p tcp --syn -j syn-flood-input
    iptables -A syn-flood-input -p tcp --syn -m limit --limit $psecin/m --limit-burst $burin -j RETURN
    iptables -A syn-flood-input -j REJECT
    echo -ne "\n\nAdd anti-syn-flood-input rules : [OK]\n\n"
    iptables -N syn-flood-forward
    iptables -A FORWARD -p tcp --syn -j syn-flood-forward
    iptables -A syn-flood-forward -p tcp --syn -m limit --limit $psecfo/s --limit-burst $burfo -j RETURN
    iptables -A syn-flood-forward -j REJECT
    echo -ne "\n\nAdd anti-syn-flood-forward rules : [OK]\n\n"
    sysctl -w net.ipv4.tcp_max_syn_backlog=3000
    sysctl -w net.ipv4.tcp_synack_retries=1
    sysctl -w net.ipv4.tcp_syn_retries=1
}
op_del_rules () {
    iptables -D syn-flood-input -p tcp --syn -m limit --limit $psecin/m --limit-burst $burin -j RETURN
    iptables -D syn-flood-input -j REJECT
    iptables -D INPUT -p tcp --syn -j syn-flood-input
    iptables -F syn-flood-input
    iptables -X syn-flood-input
    echo -ne "\n\nDel anti-syn-flood-input rules : [OK]\n\n"
    iptables -D syn-flood-forward -p tcp --syn -m limit --limit $psecfo/s --limit-burst $burfo -j RETURN
    iptables -D syn-flood-forward -j REJECT
    iptables -D FORWARD -p tcp --syn -j syn-flood-forward
    iptables -F syn-flood-forward
    iptables -X syn-flood-forward
    echo -ne "\n\nDel anti-syn-flood-forward rules : [OK]\n\n"
    sysctl -w net.ipv4.tcp_max_syn_backlog=1000
    sysctl -w net.ipv4.tcp_synack_retries=5
    sysctl -w net.ipv4.tcp_syn_retries=5
}

if [ $# -lt 1 ]; then 
    echo -ne "\n\nUsage :\t $0  action[0: off\t1: on]\n\n"
fi

if [ $1 -eq 1 ]; then
    iptables-save | grep "syn-flood" > /dev/null 2>&1
    if [ $? -eq  1 ]; then
        echo -ne "\nAdd rules : "
        op_add_rules
    else
        echo -ne "\nWARNNING : \033[5;31;40mrules already exist !!!\033[0m\n"
    fi
else
    iptables-save | grep "syn-flood" > /dev/null 2>&1
    if [ $? -eq  0 ]; then
        echo -ne "\nDel rules \n"
        op_del_rules
    else
        echo -ne "\nWARNNING : \033[5;31;40mrules already not exist !!!\033[0m\n"
    fi
fi

echo -ne "\n\nEXIT_SUCCESS\n\n"

