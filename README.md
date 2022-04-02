# OPF
An OpenBSD firewall web interface

This project is a bit of a slow burn, and a hacky one at that. I'm not sure if it will ever become anything significant, but I enjoy working on it.

## Packages for OpenBSD box
- `prometheus`
- `node_exporter`

## Prometheus
- Install and then uninstall the system prometheus to setup the user accounts because lazy
- Build prometheus from source using [this](https://github.com/ston1th/prometheus/tree/mmap_openbsd) branch
- Install it under `/opt` and create the file `/etc/rc.d/prometheus_opt`
  ```sh
  #!/bin/ksh
  #
  # $OpenBSD: prometheus.rc,v 1.3 2021/02/27 09:28:50 ajacoutot Exp $

  daemon="/opt/prometheus/prometheus"
  daemon_flags="--config.file /etc/prometheus/prometheus.yml"
  daemon_flags="${daemon_flags} --storage.tsdb.path '/var/prometheus'"
  daemon_logger="daemon.info"
  daemon_user="_prometheus"

  . /etc/rc.d/rc.subr

  pexp="${daemon}.*"
  rc_bg=YES
  rc_reload=NO

  rc_cmd $1
  ```

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
