#!/bin/bash - 
#===============================================================================
#
#          FILE:  connlimit.sh
# 
#         USAGE:  ./connlimit.sh  0/1
# 
#   DESCRIPTION:  
# 
#       OPTIONS: ---
#  REQUIREMENTS: ---
#          BUGS: ---
#         NOTES: ---
#        AUTHOR: bigdog()
#       COMPANY: 
#       CREATED: 04/07/2011 02:42:34 PM CST
#      REVISION: 1.01
#===============================================================================
set -o nounset                              # Treat unset variables as an error



#-------------------------------------------------------------------------------
#  Usage
#-------------------------------------------------------------------------------
usage() {
    echo "$0  0/1"
}


#-------------------------------------------------------------------------------
#  添加
#-------------------------------------------------------------------------------
add_rules () {
    sysctl -w net.ipv4.tcp_max_syn_backlog=3000
    sysctl -w net.ipv4.tcp_synack_retries=1
    sysctl -w net.ipv4.tcp_syn_retries=1

    # 限制单个IP的并发链接数为4
    iptables -I INPUT -p tcp -m connlimit --connlimit-above 4 -j REJECT

    # 限制单个c类子网的并发链接数量
    iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT
    iptables -A INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK ACK -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT
    # 30秒内只能与设备建立3个新的链接
    #   --update 是指每次建立连接都更新列表
    #   --seconds必须与--rcheck或者--update同时使用
    #   --hitcount必须与--rcheck或者--update同时使用
    iptables -I INPUT -p tcp -m tcp  -m state --state NEW -m recent --update --seconds 15 --hitcount 3 --name DDOS -j REJECT --reject-with tcp-reset
    iptables -A INPUT -p tcp -m tcp -m state --state NEW -m recent --set --name DDOS -j ACCEPT
}


#-------------------------------------------------------------------------------
#  删除
#-------------------------------------------------------------------------------
del_rules () {
    sysctl -w net.ipv4.tcp_max_syn_backlog=1000
    sysctl -w net.ipv4.tcp_synack_retries=5
    sysctl -w net.ipv4.tcp_syn_retries=5
    iptables -D INPUT -p tcp  -m connlimit --connlimit-above 4 -j REJECT
    iptables -D INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT
    iptables -D INPUT -p tcp --tcp-flags FIN,SYN,RST,ACK ACK -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT
    iptables -D INPUT -p tcp -m tcp -m state --state NEW -m recent --update --seconds 15 --hitcount 3 --name DDOS -j REJECT --reject-with tcp-reset
    iptables -D INPUT -p tcp -m tcp -m state --state NEW -m recent --set --name DDOS -j ACCEPT
}

#-------------------------------------------------------------------------------
#  judge arg num
#-------------------------------------------------------------------------------
if [ $# -lt 1 ]; then
    usage
    exit
fi

#-------------------------------------------------------------------------------
#  if off or open
#-------------------------------------------------------------------------------
if [ $1 -eq 0 ]; then
    iptables-save | grep -i recent >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        del_rules
    else
        echo -ne "\ndo nothing, beacase not set rules\n"
    fi
else
    iptables-save | grep -i recent >/dev/null 2>&1
    if [ $? -eq 1 ]; then
        add_rules
    fi
fi


#-------------------------------------------------------------------------------
#  print exit success msg
#-------------------------------------------------------------------------------
echo -ne "\nstatus : [\033[0;31;40mOK\033[0m]\n\n"
