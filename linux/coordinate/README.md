# Coordinate

Automation tool that runs many scripts concurrently over SSH on many remote boxes.

This is meant to be used to deploy minute-zero persistence in red team events, or remediation in blue team events.

# Usage

See `coordinate -h`.

Examples:

``` bash
# Run patch.sh on 192.168.1.0/26
coordinate -t 192.168.1.0/26 -u root -p Password1! patch.sh

# Run all scripts in /opt/scripts/ on 10.0.0.5 with password supplied from stdin
coordinate -t 10.0.0.5 -u root /opt/scripts/*.sh

# Run check_vuln.sh and patch_vuln.sh on those machines, and only print errors
coordinate -e -t 172.16.0.0/27,192.168.1.15-192.168.1.20,127.0.0.1 -u root -p Password1! *vuln.sh
```
