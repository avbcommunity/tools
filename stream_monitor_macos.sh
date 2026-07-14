#!/bin/sh
# Supervisor for stream_monitor_macos: relaunches after the suicide watchdog exits a
# HAL-hung instance (rc=42) or any other death. A fresh process gets a
# fresh coreaudiod client connection, which is the only reliable way
# out of a wedged HAL call.
while true; do
  /Users/user/stream_monitor_macos run "$@"
  rc=$?
  echo "stream_monitor_macos: exited rc=$rc, relaunch in 3s"
  sleep 3
done
