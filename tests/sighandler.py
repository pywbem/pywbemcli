#!/usr/bin/env python

"""
Demonstrate signal handling in Python.

Usage:
- run this script, it will show the process ID
- send OS-level signals to the process ID of the script (e.g. 'kill -n 2 PID')
"""

import sys
import os
import platform
import signal
import time

SLEEP_TIME = 300

def sigstr(signal_number):
    try:
        return signal.strsignal(signal_number)
    except AttributeError:
        return '?'

class SignalIndication(Exception):
    pass

def signal_handler(signal_number, frame):
    print("handler: Received signal {} ({})".
          format(signal_number, sigstr(signal_number)))
    raise SignalIndication(
        "signal {} ({})".format(signal_number, sigstr(signal_number)))

def register_handler(signal_name, condition=True):
    if condition:
        signal_number = getattr(signal, signal_name)
        print("main: Registering handler for signal {} ({}, {})".
              format(signal_number, signal_name, sigstr(signal_number)))
        signal.signal(signal_number, signal_handler)

print("main: Python: {}".format(sys.version.replace('\n', '')))
print("main: Platform: {} / {}".format(sys.platform, platform.platform()))
print("main: Process: {}".format(os.getpid()))
register_handler('SIGINT')
register_handler('SIGILL')
register_handler('SIGABRT')
register_handler('SIGFPE')
register_handler('SIGSEGV')
register_handler('SIGTERM')
register_handler('SIGBREAK', sys.platform == 'win32')
while True:
    print("main: Sleeping for {} sec".format(SLEEP_TIME))
    try:
        time.sleep(SLEEP_TIME)
    except Exception as exc:
        print("main: Caught {}: {}".format(exc.__class__.__name__, exc))
