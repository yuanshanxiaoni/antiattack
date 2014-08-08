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


#-------------------------------------------------------------------------------
#  limited packet of input ping-packets 
#  nomorl : 0.2 times per sec
#  now    : limited 1 icmp echo-request packet per sec 
#  option : --limit 1/s  per sec ;  --limit 1/m per min 
#           --limit-burst allowed to trigger rules' max times 
#-------------------------------------------------------------------------------
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 1 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

