#!/usr/bin/env python
import argparse

from Anomalies.DetectionMethods.NoOpenSessionInAuthlogDetector import NoOpenSessionInAuthlogDetector
from EventsParser import iterate_events


def main(auth_log_file: str):
    detectors = (NoOpenSessionInAuthlogDetector(), )  # It will be several detectors some day.
    for event in iterate_events(auth_log_file=auth_log_file):
        for detector in detectors:
            detector.consume(event=event)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--auth_log_file", help="auth.log file path", default="/var/log/auth.log")
    args = parser.parse_args()
    main(auth_log_file=args.auth_log_file)
