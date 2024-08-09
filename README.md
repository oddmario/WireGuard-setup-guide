# Setup a WireGuard tunnel between two Linux servers

TL;DR network engineering is hard 🫠

## Server A
It is the "WireGuard VPS" which we are going to use the IP address of instead of the IP address of Server B.

One recommended provider for Server A is BuyVM.net [especially with their DDoS protected IPs]

## Server B
It is the "backend server" or the destination server. i.e. the server which we are trying to hide/protect the IP address of.

## This guide covers
- Setting up a WireGuard tunnel to link between two Linux servers (server A and server B)
- Setting up the proper routing to make server A forward all the traffic to & from server B through the tunnel.

If you would like to use GRE (or OpenVPN) instead of a WireGuard tunnel to link between the two servers, you can absolutely give that a go!

Generally, we just need a way to link between the two servers (either WireGuard, GRE or even OpenVPN). Then the rest of the commands to setup the routing through iproute2 and iptables should be similar.

## Requirements
- Server A needs to have at least one primary public IP address that we are going to use as the peer address for our WireGuard tunnel(s).
- And similary, Server B needs to have at least one primary public IP address so we can use it inside the tunnel.
- Make sure the following packages are installed on the systems of both server A and server B:
     - iproute2 (the `ip` command)
     - ethtool
     - iproute-tc (the `tc` command)
     - wireguard (refer to https://www.wireguard.com/install/)

-----

## First things first, WireGuard is encrypted?
And thus we need to generate our keys first.

On server A, run the below commands to generate a private key, then output the public key of it:
```
umask 077
wg genkey > wg_private
wg pubkey < wg_private
```
keep the `public key of server A` somewhere safe and sound because we are about to use it in our scripts below.

Then on server B, run the same below commands to generate a private key, then output the public key of it:
```
umask 077
wg genkey > wg_private
wg pubkey < wg_private
```
and once again, keep the `public key of server B` somewhere safe and sound because we are about to use it in our scripts below.

## Tunnel setup scripts

`makeWG.sh` on Server A:
```
#!/bin/bash

# This script is placed on the WireGuard VPS

#
# Variables
#

# WG_VPS_IP below doesn't have to be the main IP address of the WireGuard VPS. you can put an additional/secondary public IP linked to the WireGuard VPS here if that's what you are attempting to make the WireGuard tunnel use to forward all the traffic to server B. However if the WireGuard VPS has only one public IP (which is the main IP address), you can put it here.
WG_VPS_IP="[the public ip address of the wireguard vps that you are attempting to make its traffic forwarded to the backend server]"
BACKEND_IP="[backend server public ip address here]"
WG_VPS_MAIN_INTERFACE="eth0"

BACKEND_WG_PUBKEY="" # put the public key of server B here

WG_TUNNEL_INTERFACE_NAME="wg0"
WG_TUNNEL_GATEWAY_IP="192.168.168.0"
WG_TUNNEL_WGVPS_IP="192.168.168.1"
WG_TUNNEL_BACKEND_IP="192.168.168.2"

WG_PRIVATE_KEY_FILE_PATH="/root/wg_private"
WG_LISTEN_PORT="51820"
WG_BACKEND_LISTEN_PORT="51820"

# ----------------------------------

# stop & disable the firewall to avoid issues
systemctl stop firewalld
systemctl disable firewalld

# enable the required kernel tweaks for the purpose of tunneling
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.$WG_VPS_MAIN_INTERFACE.proxy_arp=1
## https://serverfault.com/a/359232/554686
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1

# additional kernel tweaks
sysctl -w net.ipv4.tcp_mtu_probing=1
## Disabling IPv6 below is optional
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
sysctl -w fs.file-max=2097152
sysctl -w fs.inotify.max_user_instances=1048576
sysctl -w fs.inotify.max_user_watches=1048576
sysctl -w fs.nr_open=1048576
sysctl -w fs.aio-max-nr=1048576
sysctl -w net.core.somaxconn=65535
sysctl -w net.core.netdev_max_backlog=16384
sysctl -w net.core.dev_weight=64
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.nf_conntrack_max=1000000
sysctl -w net.netfilter.nf_conntrack_max=1000000
sysctl -w net.ipv4.tcp_max_tw_buckets=1440000
sysctl -w net.unix.max_dgram_qlen=50
sysctl -w net.ipv4.neigh.default.proxy_qlen=96
sysctl -w net.ipv4.neigh.default.unres_qlen=6
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=fq
sysctl -w net.ipv4.tcp_notsent_lowat=16384

# tune the networking
modprobe tcp_bbr
tc qdisc replace dev $WG_VPS_MAIN_INTERFACE root fq
ip link set $WG_VPS_MAIN_INTERFACE txqueuelen 15000
ethtool -K $WG_VPS_MAIN_INTERFACE gro off gso off tso off

# clear all iptables rules
iptables -F

# we are setting up the wireguard interface manually using the `ip` (iproute2) commands, then we will configure the wireguard server & peer later using `wg set`.
# ... there are other tools that make setting this up possible through a .conf file (the wg-quick command). however wg-quick automatically sets up the routing for us, which is something that we don't want because we will use our own custom routes later.
# ... generally, wg-quick is just a wrapper that does the same thing that we are about to do, but we don't want the routing that it does. hence why we're doing all this manually.
# ref: https://www.reddit.com/r/WireGuard/comments/m8jwnt/comment/gri660w/?utm_source=share&utm_medium=mweb3x&utm_name=mweb3xcss&utm_term=1&utm_content=share_button
# ref: https://superuser.com/a/1744609/936854
# ref: https://engineerworkshop.com/blog/how-to-set-up-a-wireguard-client-on-linux-with-conf-file/

# add a new wireguard interface
ip link add $WG_TUNNEL_INTERFACE_NAME type wireguard

# add $WG_TUNNEL_WGVPS_IP as an IP for peer A on our newly created wireguard interface
ip addr add $WG_TUNNEL_WGVPS_IP/24 dev $WG_TUNNEL_INTERFACE_NAME

# set the private key for the wg interface then bring the wg interface up
wg set $WG_TUNNEL_INTERFACE_NAME private-key $WG_PRIVATE_KEY_FILE_PATH
ip link set $WG_TUNNEL_INTERFACE_NAME up

# add server B as a peer on our wireguard interface
wg set $WG_TUNNEL_INTERFACE_NAME listen-port $WG_LISTEN_PORT peer $BACKEND_WG_PUBKEY allowed-ips $WG_TUNNEL_BACKEND_IP/32 endpoint $BACKEND_IP:$WG_BACKEND_LISTEN_PORT persistent-keepalive 25

# ensure that iptables won't block any traffic from/to peer B
iptables -A FORWARD -i wg+ -j ACCEPT
iptables -A FORWARD -d $WG_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -s $WG_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# forward any traffic coming from the $WG_TUNNEL_GATEWAY_IP/24 subnet to the public IP of server A. this will give server B the ability to use the network of server A through the wireguard tunnel
iptables -t nat -A POSTROUTING -s $WG_TUNNEL_GATEWAY_IP/24 ! -o wg+ -j SNAT --to-source $WG_VPS_IP

# forward any traffic coming to the public IP of server A to server B. be warned that upon running the below command, you won't be able to access the original server A through its public IP anymore. it will mostly connect you to server B instead
iptables -t nat -A PREROUTING -d $WG_VPS_IP -j DNAT --to-destination $WG_TUNNEL_BACKEND_IP

# tune the wireguard interface
tc qdisc replace dev $WG_TUNNEL_INTERFACE_NAME root fq
ip link set $WG_TUNNEL_INTERFACE_NAME txqueuelen 15000
ethtool -K $WG_TUNNEL_INTERFACE_NAME gro off gso off tso off
```

`delWG.sh` on Server A:
```
#!/bin/bash

# This script is placed on the WireGuard VPS

#
# Variables
#

# WG_VPS_IP below doesn't have to be the main IP address of the WireGuard VPS. you can put an additional/secondary public IP linked to the WireGuard VPS here if that's what you are attempting to make the WireGuard tunnel use to forward all the traffic to server B. However if the WireGuard VPS has only one public IP (which is the main IP address), you can put it here.
WG_VPS_IP="[the public ip address of the wireguard vps that you are attempting to make its traffic forwarded to the backend server]"

WG_TUNNEL_INTERFACE_NAME="wg0"
WG_TUNNEL_GATEWAY_IP="192.168.168.0"
WG_TUNNEL_WGVPS_IP="192.168.168.1"
WG_TUNNEL_BACKEND_IP="192.168.168.2"

# ----------------------------------

iptables -D FORWARD -d $WG_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -D FORWARD -s $WG_TUNNEL_BACKEND_IP -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -D POSTROUTING -s $WG_TUNNEL_GATEWAY_IP/24 ! -o wg+ -j SNAT --to-source $WG_VPS_IP
iptables -t nat -D PREROUTING -d $WG_VPS_IP -j DNAT --to-destination $WG_TUNNEL_BACKEND_IP
ip addr del $WG_TUNNEL_WGVPS_IP/24 dev $WG_TUNNEL_INTERFACE_NAME
ip link set $WG_TUNNEL_INTERFACE_NAME down
ip link del $WG_TUNNEL_INTERFACE_NAME
```

`makeWG.sh` on Server B:
```
#!/bin/bash

# This script is placed on the backend server

#
# Variables
#

WG_VPS_MAIN_IP="[the main public ip address of the wireguard vps here]" # NOTE: this is recommended to be the main public IP of the WireGuard VPS. even if you are trying to use an additional IP that belongs to the WireGuard VPS, it's nicer to put the main IP address here.

WG_VPS_WG_PUBKEY="" # put the public key of server A here

WG_TUNNEL_INTERFACE_NAME="wg0"
WG_TUNNEL_GATEWAY_IP="192.168.168.0"
WG_TUNNEL_WGVPS_IP="192.168.168.1"
WG_TUNNEL_BACKEND_IP="192.168.168.2"

WG_TUNNEL_RTTABLES_ID="100"
WG_TUNNEL_RTTABLES_NAME="WGTUN"

WG_PRIVATE_KEY_FILE_PATH="/root/wg_private"
WG_LISTEN_PORT="51820"
WG_WG_VPS_LISTEN_PORT="51820"

# ----------------------------------

# we are setting up the wireguard interface manually using the `ip` (iproute2) commands, then we will configure the wireguard server & peer later using `wg set`.
# ... there are other tools that make setting this up possible through a .conf file (the wg-quick command). however wg-quick automatically sets up the routing for us, which is something that we don't want because we will use our own custom routes later.
# ... generally, wg-quick is just a wrapper that does the same thing that we are about to do, but we don't want the routing that it does. hence why we're doing all this manually.
# ref: https://www.reddit.com/r/WireGuard/comments/m8jwnt/comment/gri660w/?utm_source=share&utm_medium=mweb3x&utm_name=mweb3xcss&utm_term=1&utm_content=share_button
# ref: https://superuser.com/a/1744609/936854
# ref: https://engineerworkshop.com/blog/how-to-set-up-a-wireguard-client-on-linux-with-conf-file/

# add a new wireguard interface
ip link add $WG_TUNNEL_INTERFACE_NAME type wireguard

# add $WG_TUNNEL_BACKEND_IP as an IP for peer B on our newly created wireguard interface
ip addr add $WG_TUNNEL_BACKEND_IP/24 dev $WG_TUNNEL_INTERFACE_NAME

# set the private key for the wg interface then bring the wg interface up
wg set $WG_TUNNEL_INTERFACE_NAME private-key $WG_PRIVATE_KEY_FILE_PATH
ip link set $WG_TUNNEL_INTERFACE_NAME up

# add server A as a peer on our wireguard interface. we need to allow all the IPs to be able to use the public IP of server A
wg set $WG_TUNNEL_INTERFACE_NAME listen-port $WG_LISTEN_PORT peer $WG_VPS_WG_PUBKEY allowed-ips 0.0.0.0/0,::/0 endpoint $WG_VPS_MAIN_IP:$WG_WG_VPS_LISTEN_PORT persistent-keepalive 25

# setup the routing table if necessary
if ! grep -Fxq "$WG_TUNNEL_RTTABLES_ID $WG_TUNNEL_RTTABLES_NAME" /etc/iproute2/rt_tables
then
     echo "$WG_TUNNEL_RTTABLES_ID $WG_TUNNEL_RTTABLES_NAME" >> /etc/iproute2/rt_tables
fi

# the below command tells the system to forward any traffic, coming from an interface with an IP that belongs to the $WG_TUNNEL_GATEWAY_IP/24 subnet, to the $WG_TUNNEL_RTTABLES_NAME routing table
ip rule add from $WG_TUNNEL_GATEWAY_IP/24 table $WG_TUNNEL_RTTABLES_NAME

# the below commands forward any traffic coming from the $WG_TUNNEL_RTTABLES_NAME routing table to $WG_TUNNEL_WGVPS_IP, which is the peer A server
ip route add default via $WG_TUNNEL_WGVPS_IP table $WG_TUNNEL_RTTABLES_NAME

# tune the wireguard interface
tc qdisc replace dev $WG_TUNNEL_INTERFACE_NAME root fq
ip link set $WG_TUNNEL_INTERFACE_NAME txqueuelen 15000
ethtool -K $WG_TUNNEL_INTERFACE_NAME gro off gso off tso off
```

`delWG.sh` on Server B:
```
#!/bin/bash

# This script is placed on the backend server

#
# Variables
#

WG_TUNNEL_INTERFACE_NAME="wg0"
WG_TUNNEL_GATEWAY_IP="192.168.168.0"
WG_TUNNEL_WGVPS_IP="192.168.168.1"
WG_TUNNEL_BACKEND_IP="192.168.168.2"

WG_TUNNEL_RTTABLES_NAME="WGTUN"

# ----------------------------------

ip route del default via $WG_TUNNEL_WGVPS_IP table $WG_TUNNEL_RTTABLES_NAME
ip rule del from $WG_TUNNEL_GATEWAY_IP/24 table $WG_TUNNEL_RTTABLES_NAME
ip addr del $WG_TUNNEL_BACKEND_IP/24 dev $WG_TUNNEL_INTERFACE_NAME
ip link set $WG_TUNNEL_INTERFACE_NAME down
ip link del $WG_TUNNEL_INTERFACE_NAME
```

-----

## Notes

> 📌 each individual note is prefixed with a number. any dotted points are sub-points of a note.

1. On the WireGuard VPS [server A]:
  * It is recommended to use AlmaLinux
  * Make sure the system is up to date (dnf update)
  * Disable SELinux permanently
  * Add this to `/etc/security/limits.conf`:
    ```
    * soft nproc 1048576
    * hard nproc 1048576
    * soft nofile 1048576
    * hard nofile 1048576
    * soft stack 1048576
    * hard stack 1048576
    * soft memlock unlimited
    * hard memlock unlimited
    ```
  * Reboot the VPS after updating the system & disabling SELinux

2. A bad provider for the WireGuard tunnel will cause packet loss.
     An example of that is Aeza.net. See https://lowendtalk.com/discussion/192513/aeza-sweden-and-probably-other-locations-network-issues

3. Setting the incorrect MTU for the wg interface will cause packet loss and/or slow connectivity through the tunnel.
     It is recommended to always keep the default MTU values set by the provider, WireGuard and Linux.

     However, if this can't work for you, see https://superuser.com/questions/1537638/wireguard-tunnel-slow-and-intermittent/1538495#1538495 & https://gist.github.com/nitred/f16850ca48c48c79bf422e90ee5b9d95

4. If you are facing issues after setting the WireGuard tunnel up, try disabling the firewall (ufw/firewalld) on the destination (backend) server [if it's enabled].

     If this solves the problem but you would like to keep your firewall enabled, make sure the public IP address(es) of the WireGuard VPS and the private IP address(es) of the WireGuard VPS on the WireGuard tunnel (e.g. 192.168.168.1) are trusted on the firewall of the backend server.

5. ⚠️ If you have multiple IP addresses on your WireGuard VPS, make sure they are linked to the operating system first before attempting to involve them in a WireGuard tunnel! **This is super important! you can't magically start using an IP address when the operating system does not know about it.**

     For example, if your WireGuard VPS has the public IP address `a.b.c.d` as the main IP, and it also has `e.f.g.h` as an additional IP. Make sure the latter is configured on the WireGuard VPS system.

     On AlmaLinux this can be done by creating `/etc/sysconfig/network-scripts/ifcfg-eth0:1` and placing the following in it:
     ```
     DEVICE=eth0:1
     IPADDR=e.f.g.h
     NETMASK=[netmask here]
     GATEWAY=[gateway here]
     BOOTPROTO=none
     IPV4_FAILURE_FATAL=no
     PROXY_METHOD=none
     ```

     Make sure to replace everything with their proper values then restart the network service using `systemctl restart NetworkManager.service && sleep 5 && nmcli networking off && nmcli networking on`
     
     ⚠️ **NOTE:** You must restart your WireGuard tunnel (or all of your tunnels if you have multiple) after restarting the networking. This can be done by `./delWG.sh && ./makeWG.sh` [make sure to do the same for all your WG tunnels if you have multiple scripts].

     You can absolutely do the same for all the IP addresses you would like to link. Just replace the `eth0:1` with `eth0:2`, etc.

6. If you have multiple IP addresses on the WireGuard VPS and you would like to use them to forward either to **multiple different backend servers** or to **the same backend server**, you can create multiple WireGuard tunnels.

     On both the WireGuard VPS (Server A) and the backend server (Server B), create new `makeWG-2.sh` and `delWG-2.sh` files so we can create new WireGuard setup scripts. The content of the files should be the same scripts that are at the top of this guide.

     Then edit this configurable part on the new scripts:
     ```
     WG_TUNNEL_INTERFACE_NAME="wg0"
     WG_TUNNEL_GATEWAY_IP="192.168.168.0"
     WG_TUNNEL_WGVPS_IP="192.168.168.1"
     WG_TUNNEL_BACKEND_IP="192.168.168.2"
    
     WG_TUNNEL_RTTABLES_ID="100"
     WG_TUNNEL_RTTABLES_NAME="WGTUN"

     WG_PRIVATE_KEY_FILE_PATH="/root/wg_private"
     WG_LISTEN_PORT="51820"
     WG_WG_VPS (or BACKEND)_LISTEN_PORT="51820"
     ```

     to be:

     ```
     WG_TUNNEL_INTERFACE_NAME="wg1"
     WG_TUNNEL_GATEWAY_IP="192.168.169.0" # NOTE: uses 169 instead of 168
     WG_TUNNEL_WGVPS_IP="192.168.169.1" # NOTE: uses 169 instead of 168
     WG_TUNNEL_BACKEND_IP="192.168.169.2" # NOTE: uses 169 instead of 168
    
     WG_TUNNEL_RTTABLES_ID="200"
     WG_TUNNEL_RTTABLES_NAME="WGTUN2"

     WG_PRIVATE_KEY_FILE_PATH="/root/wg_private2" # make sure to generate this private key as well
     WG_LISTEN_PORT="51821" # must change the ports because port 51820 will be already in use by the first WireGuard tunnel
     WG_WG_VPS (or BACKEND)_LISTEN_PORT="51821"
     ```

     then modify `WG_VPS_IP` and `BACKEND_IP` to be the additional public IP of the WireGuard VPS and the IP of the new (or the same) backend server respectively. And make sure to modify the rest of the variables as well (public keys, etc).

     ⚠️ **Also, super importantly,** make sure that the `iptables -F` line on the `makeWG.sh` script of the WireGuard VPS is executed only once by ONLY ONE script. Otherwise the script of each WG tunnel will keep clearing the iptables rules as they are executed, resulting in an unwanted behaviour.

     Now running `makeWG-2.sh` on both the backend and the WireGuard VPS should set this up properly [make sure `makeWG.sh` was run first because it has the `iptables -F` command which clears any unwanted iptables leftovers].
     
     Accessing the additional IP of the WireGuard VPS should forward the traffic to the same backend server that we set the main WireGuard tunnel up for. To confirm the setup, run this on the backend server:
     ```
     curl --interface 192.168.168.2 https://icanhazip.com
     curl --interface 192.168.169.2 https://icanhazip.com
     ```
     the first command should output the first IP address that we initially set up for the WG tunnel. and the second command should output the additional IP address that we have just linked to the WG tunnel.

     You can do the same for as many additional IP addresses as you want. Just create `makeWG-3.sh` and `delWG-3.sh`, and change the `192.168.169` part to something else like `192.168.170`

7. To make the WireGuard tunnel(s) persistent, create a file at `/etc/systemd/system/wgtunnels.service` with the following content:

     ```
     [Unit]
     Description=WGInitService
     After=network.target

     [Service]
     Type=oneshot
     ExecStart=/root/makeWG.sh
     ExecStop=/root/delWG.sh
     User=root
     RemainAfterExit=yes

     [Install]
     WantedBy=multi-user.target
     ```

     Then run `systemctl daemon-reload`, `systemctl enable wgtunnels.service`.

     This will:
     - make the WG tunnel(s) automatically get created on the system boot.
     - make the management of the WG tunnel(s) easier. just use `systemctl stop wgtunnels.service` to delete the tunnel(s), and the same for `start`.

     Note that if you have multiple WireGuard tunnels setup by multiple scripts, it is better to create two scripts called `initWG.sh` and `deinitWG.sh`
     
     initWG.sh:
     ```
     #!/bin/bash

     /root/makeWG.sh
     /root/makeWG-2.sh
     ```
     
     deinitWG.sh:
     ```
     #!/bin/bash

     /root/delWG-2.sh
     /root/delWG.sh
     ```
     
     ⚠️ Notice how `deinitWG` is in the inversed order of `initWG` (the last executed `makeWG` script is the first executed `delWG` script).
     
     Then edit `/etc/systemd/system/wgtunnels.service` to execute the newly created managing scripts instead:
     ```
     ExecStart=/root/initWG.sh
     ExecStop=/root/deinitWG.sh
     ```

8. If you want to make one of the WireGuard VPS IPs act like the primary IP of the backend server (i.e. all the internet requests on the backend server will see the WireGuard VPS IP as the public IP of the backend server):
     
     You will need to use these scripts **on server B [the backend server]** instead of the ones that were shown initially at the top of this whole guide [they are the same scripts with just a few additional commands]:
     
     makeWG.sh on Server B (the backend server):
     ```
     #!/bin/bash
    
     # This script is placed on the backend server
    
     #
     # Variables
     #
    
     WG_VPS_MAIN_IP="[the main public ip address of the wireguard vps here]" # NOTE: this is recommended to be the main public IP of the WireGuard VPS. even if you are trying to use an additional IP that belongs to the WireGuard VPS, it's nicer to put the main IP address here.
    
     WG_VPS_WG_PUBKEY="" # put the public key of server A here
    
     WG_TUNNEL_INTERFACE_NAME="wg0"
     WG_TUNNEL_GATEWAY_IP="192.168.168.0"
     WG_TUNNEL_WGVPS_IP="192.168.168.1"
     WG_TUNNEL_BACKEND_IP="192.168.168.2"
    
     WG_TUNNEL_RTTABLES_ID="100"
     WG_TUNNEL_RTTABLES_NAME="WGTUN"

     WG_PRIVATE_KEY_FILE_PATH="/root/wg_private"
     WG_LISTEN_PORT="51820"
     WG_WG_VPS_LISTEN_PORT="51820"

     BACKEND_SERVER_MAIN_INTERFACE_NAME="eth0"
    
     # ----------------------------------

     GATEWAY_IP=$(ip route show dev $BACKEND_SERVER_MAIN_INTERFACE_NAME | grep default | awk '{print $3}' | awk 'NR==1{print; exit}')

     # we are setting up the wireguard interface manually using the `ip` (iproute2) commands, then we will configure the wireguard server & peer later using `wg set`.
     # ... there are other tools that make setting this up possible through a .conf file (the wg-quick command). however wg-quick automatically sets up the routing for us, which is something that we don't want because we will use our own custom routes later.
     # ... generally, wg-quick is just a wrapper that does the same thing that we are about to do, but we don't want the routing that it does. hence why we're doing all this manually.
     # ref: https://www.reddit.com/r/WireGuard/comments/m8jwnt/comment/gri660w/?utm_source=share&utm_medium=mweb3x&utm_name=mweb3xcss&utm_term=1&utm_content=share_button
     # ref: https://superuser.com/a/1744609/936854
     # ref: https://engineerworkshop.com/blog/how-to-set-up-a-wireguard-client-on-linux-with-conf-file/
    
     # add a new wireguard interface
     ip link add $WG_TUNNEL_INTERFACE_NAME type wireguard
    
     # add $WG_TUNNEL_BACKEND_IP as an IP for peer B on our newly created wireguard interface
     ip addr add $WG_TUNNEL_BACKEND_IP/24 dev $WG_TUNNEL_INTERFACE_NAME
    
     # set the private key for the wg interface then bring the wg interface up
     wg set $WG_TUNNEL_INTERFACE_NAME private-key $WG_PRIVATE_KEY_FILE_PATH
     ip link set $WG_TUNNEL_INTERFACE_NAME up
    
     # add server A as a peer on our wireguard interface. we need to allow all the IPs to be able to use the public IP of server A
     wg set $WG_TUNNEL_INTERFACE_NAME listen-port $WG_LISTEN_PORT peer $WG_VPS_WG_PUBKEY allowed-ips 0.0.0.0/0,::/0 endpoint $WG_VPS_MAIN_IP:$WG_WG_VPS_LISTEN_PORT persistent-keepalive 25
    
     # setup the routing table if necessary
     if ! grep -Fxq "$WG_TUNNEL_RTTABLES_ID $WG_TUNNEL_RTTABLES_NAME" /etc/iproute2/rt_tables
     then
          echo "$WG_TUNNEL_RTTABLES_ID $WG_TUNNEL_RTTABLES_NAME" >> /etc/iproute2/rt_tables
     fi
    
     # the below command tells the system to forward any traffic, coming from an interface with an IP that belongs to the $WG_TUNNEL_GATEWAY_IP/24 subnet, to the $WG_TUNNEL_RTTABLES_NAME routing table
     ip rule add from $WG_TUNNEL_GATEWAY_IP/24 table $WG_TUNNEL_RTTABLES_NAME
    
     # the below commands forward any traffic coming from the $WG_TUNNEL_RTTABLES_NAME routing table to $WG_TUNNEL_WGVPS_IP, which is the peer A server
     ip route add default via $WG_TUNNEL_WGVPS_IP table $WG_TUNNEL_RTTABLES_NAME

     # dns servers are required otherwise all dns resolutions will fail
     # the reason this happens is because in a command below we are about to route all the traffic through the wireguard tunnel, this also includes DNS requests
     echo 'nameserver 1.1.1.1' > /etc/resolv.conf
     echo 'nameserver 1.0.0.1' >> /etc/resolv.conf

     # finally cut over our routing
     # NOTE: this will cut all access to your original BACKEND IP!

     # route all the traffic through the wireguard tunnel. except for $WG_VPS_MAIN_IP, which still will be routed through the original gateway of server B [this server] instead.
     # the reason we put this exception is because $WG_VPS_MAIN_IP is used as the wireguard peer address for our tunnel (its the IP that connects this server to server A). we need it to be accessible so our wireguard tunnel can function properly.
     ip route add $WG_VPS_MAIN_IP via $GATEWAY_IP dev $BACKEND_SERVER_MAIN_INTERFACE_NAME onlink
     ip route replace default via $WG_TUNNEL_WGVPS_IP
    
     # tune the wireguard interface
     tc qdisc replace dev $WG_TUNNEL_INTERFACE_NAME root fq
     ip link set $WG_TUNNEL_INTERFACE_NAME txqueuelen 15000
     ethtool -K $WG_TUNNEL_INTERFACE_NAME gro off gso off tso off
     ```
     
     delWG.sh on Server B (the backend server):
     ```
     #!/bin/bash

     # This script is placed on the backend server
    
     #
     # Variables
     #

     WG_VPS_MAIN_IP="[the main public ip address of the wireguard vps here]" # NOTE: this is recommended to be the main public IP of the WireGuard VPS. even if you are trying to use an additional IP that belongs to the WireGuard VPS, it's nicer to put the main IP address here.
    
     WG_TUNNEL_INTERFACE_NAME="wg0"
     WG_TUNNEL_GATEWAY_IP="192.168.168.0"
     WG_TUNNEL_WGVPS_IP="192.168.168.1"
     WG_TUNNEL_BACKEND_IP="192.168.168.2"
    
     WG_TUNNEL_RTTABLES_NAME="WGTUN"

     BACKEND_SERVER_MAIN_INTERFACE_NAME="eth0"
    
     # ----------------------------------

     GATEWAY_IP=$(ip route show dev $BACKEND_SERVER_MAIN_INTERFACE_NAME | grep default | awk '{print $3}' | awk 'NR==1{print; exit}')

     ip route del default
     ip route del $WG_VPS_MAIN_IP via $GATEWAY_IP dev $BACKEND_SERVER_MAIN_INTERFACE_NAME onlink
     ip route replace default via $GATEWAY_IP
    
     ip route del default via $WG_TUNNEL_WGVPS_IP table $WG_TUNNEL_RTTABLES_NAME
     ip rule del from $WG_TUNNEL_GATEWAY_IP/24 table $WG_TUNNEL_RTTABLES_NAME
     ip addr del $WG_TUNNEL_BACKEND_IP/24 dev $WG_TUNNEL_INTERFACE_NAME
     ip link set $WG_TUNNEL_INTERFACE_NAME down
     ip link del $WG_TUNNEL_INTERFACE_NAME
     ```
     
     As for the scripts of server A [the WireGuard VPS], leave them unchanged.

9. Reboot the WireGuard VPS (and preferably but not necessarily the backend server[s] too) after setting up or modifying any WG tunnels to ensure that no unneeded leftovers are there. This really makes a difference most of the time.

## ⚠️ An important note if you are using BuyVM as your WireGuard VPS + a DDoS protected IP (or more) from them

Make sure that the main IP address of your BuyVM VPS is the normal non-DDoS protected IP address. You can set the main IP address through the BuyVM Stallion panel.

Also make sure to use that same normal non-DDoS protected IP address as the value of the `WG_VPS_MAIN_IP` variable in the scripts.

The main reason we do this is to avoid getting the IP address of our backend server from getting blocked by the BuyVM (Path.net) DDoS protection.

> From https://wiki.buyvm.net/doku.php/gre_tunnel:
> 
> You will always want to form your GRE with your unfiltered IP address for all GRE tunnels to make sure you don't run into any sort of MTU issues or trigger the DDOS protection.

Also as an additional precaution step, you can go to the DDoS protection panel on your BuyVM Stallion and add a firewall rule like this:
```
Source IP Address: [the public IP of the backend server]/32
Protocol: ALL (All Protocols)
Action: Allow
```

- Another note, the optimal MTU for the wg interfaces for BuyVM (**ONLY for the DDoS protected IPs**) appears to be 1360.
  > https://discord.com/channels/427396480437977118/427505056821018645/1234689531232518166
  >
  > — 04/30/2024 5:07 AM
  > 
  > hello
  > 
  > what is the wireguard mtu that has to be set? the discord link isnt working so i cant check the pin
  > 
  > exor — 04/30/2024 5:15 AM
  > 
  > Aretiger
  > 
  > —
  > 
  > 07/06/2023 10:18 AM
  > 
  > Hello! WireGuard MTU: 1360
  > 
  >  
  > Please make sure the correct MTU is set everywhere (WireGuard client-side tunnel config, server-side WireGuard configuration, plus the WireGuard tunnel interface on the server).
  > 
  > Francisco — 04/30/2024 5:37 AM
  > 
  > that mtu's just for DDOS protected IP's
  
  So in order to use this, run this command on both server A and server B [of course after setting up the tunnel using the makeWG.sh script]:
  ```
  ip link set dev wg0 mtu 1360
  ```

  And make sure to apply the same to any other WireGuard interfaces (e.g. wg1, etc) if you have multiple tunnels.

## Inspiration
- https://www.wireguard.com/quickstart/
- https://wiki.archlinux.org/title/WireGuard
- https://wiki.archlinux.org/title/WireGuard#Manual_configuration
- https://wiki.archlinux.org/title/WireGuard#Routing_all_traffic_over_WireGuard
- https://community.hetzner.com/tutorials/linux-setup-gre-tunnel
- https://wiki.buyvm.net/doku.php/gre_tunnel
- https://wiki.buyvm.net/doku.php/gre_tunnel:docker (mainly only for the formatting of the shell scripts)
- https://richardbernecker.com/configuring-a-persistent-gre-tunnel-via-systemd/
- https://github.com/klaver/sysctl
