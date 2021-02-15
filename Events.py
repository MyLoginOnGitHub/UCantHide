class EventSourceFile:
    AUTH_LOG = 1  # Event has retrieved from /var/log/auth.log file


class EventDescription:
    SESSION_OPENED = 1
    SESSION_CLOSED = 2


class Event:
    def __init__(self, source_file_code, event_datetime, description_code, application, pid, ip):
        self.sourceFileCode = source_file_code
        self.datetime = event_datetime
        self.descriptionCode = description_code
        self.application = application
        self.pid = pid
        self.ip = ip
