#!/bin/bash
# entrypoint.sh — ot-hmi simulator
#
# Starts rsyslog so /var/log/auth.log gets populated, starts sshd in the
# foreground (PID 1), and ensures the container exits if sshd dies.

set -e

# Generate host keys if missing (first boot of the image)
ssh-keygen -A 2>/dev/null || true

# Start rsyslog in the background
mkdir -p /var/log
touch /var/log/auth.log /var/log/syslog /var/log/daemon.log
chmod 644 /var/log/auth.log /var/log/syslog /var/log/daemon.log
rsyslogd 2>/dev/null || true

# Make sure auth.log is a real file we can tail (bind-mount empty dir
# case — sometimes the host bind-mount swallows our touch above)
[ -f /var/log/auth.log ] || touch /var/log/auth.log

# Echo a startup record so filebeat sees the file and starts harvesting
logger -p auth.notice "ot-hmi-water-01 sshd starting; environment=lab; plant_id=HL-WTP-01"

# Foreground sshd so the container PID 1 is the daemon
exec /usr/sbin/sshd -D -e
