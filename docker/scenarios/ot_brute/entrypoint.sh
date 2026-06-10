#!/bin/bash
# entrypoint.sh — ot-hmi simulator
#
# Starts rsyslog so /var/log/auth.log gets populated, starts sshd in the
# foreground (PID 1), and ensures the container exits if sshd dies.

set -e

# Generate host keys if missing (first boot of the image)
ssh-keygen -A 2>/dev/null || true

# Start rsyslog in the background. Two things matter for /var/log/auth.log
# to actually fill:
#   - rsyslog runs as syslog:adm, so the log files must be writable by it
#     (we pre-touch them so filebeat sees existing inodes immediately).
#   - imklog (kernel-log module) fails in unprivileged containers because
#     /proc/kmsg needs CAP_SYSLOG. We're not interested in kernel messages
#     from inside a Docker container anyway — disable it so rsyslog starts
#     clean instead of logging an error every boot.
mkdir -p /var/log
touch /var/log/auth.log /var/log/syslog /var/log/daemon.log
chown syslog:adm /var/log/auth.log /var/log/syslog /var/log/daemon.log
chmod 640 /var/log/auth.log /var/log/syslog /var/log/daemon.log
sed -i 's|^module(load="imklog".*|# module(load="imklog") disabled inside container — no CAP_SYSLOG|' /etc/rsyslog.conf
rsyslogd 2>/dev/null || true

# Echo a startup record so filebeat sees the file and starts harvesting
logger -p auth.notice "ot-hmi-water-01 sshd starting; environment=lab; plant_id=HL-WTP-01"

# Foreground sshd so the container PID 1 is the daemon. We deliberately
# do NOT pass -e: -e sends sshd logs to stderr (which docker captures
# but rsyslog never sees), so /var/log/auth.log would stay empty and
# filebeat would have nothing to ship. Without -e, sshd uses syslog,
# rsyslog routes auth.* to /var/log/auth.log, and the brute-force
# evidence becomes ingestible.
exec /usr/sbin/sshd -D
