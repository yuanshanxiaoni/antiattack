#!/bin/bash - 
#===============================================================================
#
#          FILE:  antiAttack.sh
# 
#         USAGE:  ./antiAttack.sh 
# 
#   DESCRIPTION:  防攻击脚本,可避免内网(或服务器本身)受大多数的DDOS攻击,如:
#                 syn-flooder, death-of-ping, ack-flooder, cc等.
# 
#       OPTIONS:  1: 打开防攻击脚本; 0: 关闭
#  REQUIREMENTS: 
#          BUGS:  
#         NOTES:  
#        AUTHOR:  bigdog()
#       COMPANY:  
#       CREATED:  04/08/2011 10:01:44 AM CST
#      REVISION:  1
#===============================================================================
set -o nounset                              # Treat unset variables as an error

#===  FUNCTION  ================================================================
#          NAME:  usage
#   DESCRIPTION:  script usage
#    PARAMETERS:  none
#       RETURNS:  none
#===============================================================================
usage() {
    echo -e "\nUsage : $0  Action\n"
    echo -e "\tAction :\n\t\t  0 : off\n\t\t  1 : on\n"
}

##------------------------------------------------------------------------------
## sysctl -a | grep syn 查看系统参数设置
## tcp_max_syn_backlog是SYN队列的长度 
## tcp_syncookies是一个开关, 是否打开SYN Cookie 功能,该功能可以防止部分SYN攻击;
## tcp_synack_retries和tcp_syn_retries定义SYN 的重试次数  
##------------------------------------------------------------------------------
# net.ipv4.tcp_max_syn_backlog = 1024   # default
# net.ipv4.tcp_syncookies = 0       # default
# net.ipv4.tcp_synack_retries = 5   # default
# net.ipv4.tcp_syn_retries = 5      # default
##------------------------------------------------------------------------------
## 加大SYN队列长度可以容纳更多等待连接的网络连接数
## 打开SYN Cookie功能,降低重试次数,可以阻止部分SYN攻击

set_syn_system_param () {
    sysctl -w net.ipv4.tcp_max_syn_backlog=3072
    sysctl -w net.ipv4.tcp_synack_retries=1
    sysctl -w net.ipv4.tcp_syn_retries=1
}

restore_syn_system_param () {
    sysctl -w net.ipv4.tcp_max_syn_backlog=1024
    sysctl -w net.ipv4.tcp_synack_retries=5
    sysctl -w net.ipv4.tcp_syn_retries=5
}


#===  FUNCTION  ================================================================
#          NAME:  set_rules
#   DESCRIPTION:  设置防攻击的IPTABLES规则
#    PARAMETERS:  input/forward
#       RETURNS:  0 : success;  !0 : error
#===============================================================================
set_rules () {
    if [ $# -lt 1 ]; then
        echo -ne "\nless arguments ;\n"
        return 
    fi

    if [ $1 == "input"  ]; then
        chain="INPUT"
    elif [ $1 == "forward" ]; then
        chain="FORWARD"
    else
        echo -ne "\nerror arguments ;\n"
        return
    fi


    ##### 防止同步包洪水（Sync Flood） # 
    iptables -A $chain -p tcp --syn -m limit --limit 1/s -j ACCEPT 

    ##### 限制syn并发数每秒1次，可以根据自己的需要修改防止各种端口扫描 # 
    iptables -A $chain -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 2/s -j ACCEPT 

    # 限制单个IP的并发链接数为4
    iptables -I $chain -p tcp -m connlimit --connlimit-above 4 -j REJECT

    # 限制单个c类子网的并发链接数量
    iptables -A $chain -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT
    iptables -A $chain -p tcp --tcp-flags FIN,SYN,RST,ACK ACK -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT

    # 30秒内只能与设备建立3个新的链接
    #   --update 是指每次建立连接都更新列表 --seconds必须与--rcheck或者--update同时使用
    #   --hitcount必须与--rcheck或者--update同时使用
    iptables -I $chain -p tcp -m tcp  -m state --state NEW -m recent --update --seconds 15 --hitcount 3 --name DDOSATTACK  -j REJECT --reject-with tcp-reset
    iptables -A $chain -p tcp -m tcp -m state --state NEW -m recent --set --name DDOSATTACK -j ACCEPT

    ### defenced death-of-ping and portscan
    iptables -A $chain -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

    ### display msg
    echo -e "\n\ndefensing-rules add : [\033[0;31;40mOK\033[0m]\n\n"; 

    return 0
}


#===  FUNCTION  ================================================================
#          NAME:  clear_rules
#   DESCRIPTION:  清除set_rules函数设置的规则
#    PARAMETERS:  input/forward
#       RETURNS:  0 : success 
#===============================================================================
clear_rules () {
    if [ $# -lt 1 ]; then
        echo -ne "\nless arguments ;\n"
        return 
    fi

    if [ $1 == "input"  ]; then
        chain="INPUT"
    elif [ $1 == "forward" ]; then
        chain="FORWARD"
    else
        echo -ne "\nerror arguments ;\n"
        return
    fi

    iptables -D $chain -p tcp --syn -m limit --limit 1/s -j ACCEPT 

    iptables -D $chain -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 2/s -j ACCEPT 

    iptables -D $chain -p tcp -m connlimit --connlimit-above 4 -j REJECT

    iptables -D $chain -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT
    iptables -D $chain -p tcp --tcp-flags FIN,SYN,RST,ACK ACK -m connlimit --connlimit-above 4 --connlimit-mask 32 -j REJECT

    iptables -D $chain -p tcp -m tcp  -m state --state NEW -m recent --update --seconds 15 --hitcount 3 --name DDOSATTACK  -j REJECT --reject-with tcp-reset
    iptables -D $chain -p tcp -m tcp -m state --state NEW -m recent --set --name DDOSATTACK -j ACCEPT

    iptables -D $chain -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

    ### display msg
    echo -e "\n\ndefensing-rules del : [\033[0;31;40mOK\033[0m]\n\n"; 

    return 0
}


#-------------------------------------------------------------------------------
#  judge script arg num
#-------------------------------------------------------------------------------
if [ $# -lt 1 ]; then
    usage
    exit
fi



#-------------------------------------------------------------------------------
# define chains of iptables 
#-------------------------------------------------------------------------------
dfchain="input"

#-------------------------------------------------------------------------------
#  main foundation
#-------------------------------------------------------------------------------
if [ $1 -eq 0 ] ; then
    iptables-save | grep "DDOSATTACK" >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        clear_rules $dfchain 
    else
        echo -ne "\ndo nothing, there are no rules be seted.\n\n"
        exit
    fi
elif [ $1 -eq 1 ]; then
    iptables-save | grep "DDOSATTACK" >/dev/null 2>&1
    if [ $? -eq 1 ]; then
        set_rules $dfchain 
    else
        echo -ne "\ndo nothing, rules were seted yet.\n\n"
        exit
    fi
else
    echo -ne "\nerror arguments\n"
    exit
fi

#-------------------------------------------------------------------------------
#  print exit success mesg
#-------------------------------------------------------------------------------
echo -ne "\nstatus : [\033[0;31;40mOK\033[0m]\n\n"

