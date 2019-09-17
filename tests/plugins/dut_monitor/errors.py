import pprint

class HDDMonitorError(Exception):
    """Raised when HDD consumption on DUT exceed threshold"""
    def __repr__(self):
        return pprint.pformat(self.message)


class RAMMonitorError(Exception):
    """Raised when RAM consumption on DUT exceed threshold"""
    def __repr__(self):
        return pprint.pformat(self.message)


class CPUMonitorError(Exception):
    """Raised when CPU consumption on DUT exceed threshold"""
    def __repr__(self):
        return pprint.pformat(self.message)
