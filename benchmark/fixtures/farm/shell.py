"""Calibration farm: shell construction."""

import subprocess


def ping(host):
    return subprocess.run("ping -c1 " + host, shell=True, capture_output=True)
