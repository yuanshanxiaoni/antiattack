#!/bin/bash - 
#===============================================================================
#
#          FILE:  anti_ping.sh
# 
#         USAGE:  ./anti_ping.sh 
# 
#   DESCRIPTION:  anti-ping-flood script
# 
#       OPTIONS:  ---
#  REQUIREMENTS:  ---
#          BUGS:  ---
#         NOTES:  ---
#        AUTHOR: bigdog()
#       COMPANY: 
#       CREATED: 04/01/2011 02:17:36 PM CST
#      REVISION: 1.0.1
#===============================================================================
set -o nounset                              # Treat unset variables as an error


# 用命令： 
sysctl -a | grep syn 

################################################################################# 
##### tcp_max_syn_backlog是SYN队列的长度
################################################################################# 
net.ipv4.tcp_max_syn_backlog = 1024 

################################################################################# 
##### tcp_syncookies是一个开关, 是否打开SYN Cookie 功能,该功能可以防止部分SYN攻击;
################################################################################# 
net.ipv4.tcp_syncookies = 0 

################################################################################# 
##### tcp_synack_retries和tcp_syn_retries定义SYN 的重试次数
################################################################################# 
net.ipv4.tcp_synack_retries = 5 
net.ipv4.tcp_syn_retries = 5

### 加大SYN队列长度可以容纳更多等待连接的网络连接数，
### 打开SYN Cookie功能可以阻止部分SYN攻击，降低重试次数


################################################################################# 
### 调整上述设置的方法是：
################################################################################# 
##### 增加SYN队列长度到2048：
sysctl -w net.ipv4.tcp_max_syn_backlog=2048

##### 打开SYN COOKIE功能：
sysctl -w net.ipv4.tcp_syncookies=1

##### 降低重试次数：
sysctl -w net.ipv4.tcp_synack_retries=3 
sysctl -w net.ipv4.tcp_syn_retries=3

##### 为了系统重启动时保持上述配置，可将上述命令加入到/etc/rc.d/rc.local文件中。 

##### 防止同步包洪水（Sync Flood） # 
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT 
##### 也有人写作 #
iptables -A INPUT -p tcp --syn -m limit --limit 1/s -j ACCEPT --limit 1/s 

##### 限制syn并发数每秒1次，可以根据自己的需要修改防止各种端口扫描 # 
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT 

##### Ping洪水攻击（Ping of Death） # 
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

#-------------------------------------------------------------------------------
#  防范SYN攻击设置
#-------------------------------------------------------------------------------
# 缩短SYN- Timeout时间：
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -i eth0 -m limit --limit 1/sec --limit-burst 5 -j ACCEPT

# 每秒 最多3个 syn 封包 进入 表达为 ：
iptables -N syn-flood
iptables -A INPUT -p tcp --syn -j syn-flood
iptables -A syn-flood -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j RETURN
iptables -A syn-flood -j REJECT

#-------------------------------------------------------------------------------
# 设置syncookies： 
#-------------------------------------------------------------------------------
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=3000
sysctl -w net.ipv4.tcp_synack_retries=1
sysctl -w net.ipv4.tcp_syn_retries=1
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.forwarding=0
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.conf.default.accept_source_route=0 # 禁用icmp源路由选项

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 # 忽略icmp ping广播包，应开启
sysctl -w net.ipv4.icmp_echo_ignore_all=1 # 忽略所有icmp ping数据，覆盖上一


######## 允许单个IP的最大连接数为 50
iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j REJECT 

######## 单个IP在60秒内只允许最多新建30个连接
iptables -A INPUT -p tcp --dport 80 -m recent --name BAD_HTTP_ACCESS --update --seconds 60 \ --hitcount 30 -j REJECT 
iptables -A INPUT -p tcp --dport 80 -m recent --name BAD_HTTP_ACCESS --set -j ACCEPT


