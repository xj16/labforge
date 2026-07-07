#!/usr/bin/env python3
"""labforge SIEM viewer entrypoint.

Deployed by the Ansible ``splunk`` role next to the ``labforge_siem`` package
and run by the ``labforge-logviewer`` systemd unit. Configuration comes from
the environment (the unit sets it from the role's variables):

    LABFORGE_LOG_ROOT     directory the rsyslog collector writes into
    LABFORGE_WEB_PORT     port to bind (default 8000)
    LABFORGE_SYSLOG_PORT  collector port shown in the header (default 5514)

Pure Python standard library — no pip installs, works offline in the lab.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from labforge_siem.app import serve  # noqa: E402

if __name__ == "__main__":
    serve()
