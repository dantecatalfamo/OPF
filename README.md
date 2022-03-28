# OPF
An OpenBSD firewall web interface

This project is a bit of a slow burn, and a hacky one at that. I'm not sure if it will ever become anything significant, but I enjoy working on it.

## Packages for OpenBSD box
- `prometheus`
- `node_exporter`

## doas.conf
The following are required in `/etc/doas.conf`
```
permit nopass dante cmd /sbin/pfctl
permit nopass dante cmd pfctl
permit nopass dante cmd /sbin/ifconfig
permit nopass dante cmd ifconfig
permit nopass dante cmd /usr/sbin/rcctl
permit nopass dante cmd rcctl
permit nopass dante cmd /bin/ps
permit nopass dante cmd ps
```
