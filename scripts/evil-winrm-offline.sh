#!/bin/sh
set -eu

exec /usr/bin/ruby /opt/ctf-tools/src/evil-winrm-master/evil-winrm.rb "$@"
