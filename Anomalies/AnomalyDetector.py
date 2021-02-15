from abc import ABCMeta, abstractmethod

from Events import Event


class AnomalyDetector(metaclass=ABCMeta):

    def consume(self, event: Event):
        anomaly_description_str = self._detect_anomaly(event)
        if anomaly_description_str:
            print("[Detected] Datetime: %s IP:%s Description: %s" % (event.datetime, event.ip, anomaly_description_str))

    @abstractmethod
    def _detect_anomaly(self, event):
        raise NotImplementedError()

