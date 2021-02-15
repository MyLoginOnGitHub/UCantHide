import gzip
import itertools
import os
from datetime import datetime

from Events import Event, EventDescription, EventSourceFile
from logalyzer.ParseLogs import ParseDate, ParseIP


def _get_all_log_files(log_file_path: str):
    """
    Get all log files like "auth_log_file", "auth_log_file.1", "auth_log_file.N.gz" in time based order
    """
    all_possible_log_files = itertools.chain(
        (log_file_path, log_file_path + ".1"),  # log_file_path and log_file_path.1
        ("%s.%s.gz" % (log_file_path, x) for x in itertools.count(2))  # log_file_path.N.gz
    )
    return reversed(list(itertools.takewhile(os.path.isfile, all_possible_log_files)))


def _read_log_file(log_file: str)->bytes:
    #  /var/log/wtmp and some another useful logs are stored in binary format, so return bytes
    f = gzip.open(log_file, 'rb') if '.gz' in log_file else open(log_file, 'rb')
    return f.read()


def parse_line_of_auth_log_file(line: str, year: int)->Event:
    """
    Parses single line of auth.log file. Return None if .
    :param year: Year the line was recorded
    :return: Tuple(datetime, application, PID, description_code, username, extra_data_dict)
    """
    if not line:
        #  For example, empty line could be the first line of file after command `echo > /var/log/auth.log`
        #  Later it probably should to return some special type of Event in this case. Now just return None.
        return None
    
    application_str = line.split()[4]
    assert application_str.endswith(":")
    application_str = application_str[:-1]

    if "[" in application_str:
        application, pid_str = application_str.split("[")
        #  Now pid_str should be '<pid>]'
        assert pid_str.endswith("]")
        pid = int(pid_str[:-1])
    else:
        application, pid = application_str, 0

    dt = datetime.strptime(ParseDate(line), "%b %d %H:%M:%S").replace(year=year)
    if "session opened for user" in line:
        description = EventDescription.SESSION_OPENED
    elif "session closed for user":
        description = EventDescription.SESSION_CLOSED
    else:
        return None

    ip = ParseIP(line) or "<IP not specified>"
    return Event(
        source_file_code=EventSourceFile.AUTH_LOG,
        event_datetime=dt,
        description_code=description,
        application=application,
        pid=pid,
        ip=ip
    )


def iterate_events(auth_log_file: str = "/var/log/auth.log"):
    """
    Iterate events found in files like "auth_log_file", "auth_log_file.1", "auth_log_file.N.gz" in time based order
    """
    for current_auth_log_file in _get_all_log_files(auth_log_file):
        year_of_log_file = datetime.fromtimestamp(os.path.getmtime(current_auth_log_file)).year
        auth_log_file_content = _read_log_file(current_auth_log_file).decode()
        events = (parse_line_of_auth_log_file(line, year=year_of_log_file) for line in auth_log_file_content.splitlines())
        for event in filter(None, events):
            yield event


if __name__ == "__main__":
    for event in iterate_events():
        print(event.application, event.pid)
