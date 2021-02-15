from Anomalies.AnomalyDetector import AnomalyDetector
from Events import Event, EventDescription


class NoOpenSessionInAuthlogDetector(AnomalyDetector):
    """
    Implements method to find anomaly when there is record 'session closed' in auth.log,
                                                        but this session has never been opened.
    This could happens if an attacker has:
        1) authenticated by ssh
        2) cleaned auth.log (by `echo > /var/log/auth.log` or by more advanced method)
        3) logout
    Then an attacker logout, the record 'session closed' has appeared in the log file.
    """

    def __init__(self):
        self.__openedSessionsPid = set()

    def _detect_anomaly(self, event: Event):
        if not event.pid or not event.application == "sshd":
            return

        if event.descriptionCode == EventDescription.SESSION_OPENED:
            self.__openedSessionsPid.add(event.pid)
        elif event.descriptionCode == EventDescription.SESSION_CLOSED:
            try:
                self.__openedSessionsPid.remove(event.pid)
            except KeyError:
                return "Session with pid %s closed, but it has never been opened. " + \
                       "This could happened if an attacker has authenticated by ssh, and has cleaned auth.log. " + \
                       "Then an attacker logout, hence the record 'session closed' has appeared in the log file. " + \
                       "View last.log file and find the date. " + \
                       "Probably in several previous records you will find an IP address of an attacker"
