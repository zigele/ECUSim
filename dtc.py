from uds_addtion import Singleton


class DTCValue:
    def __init__(self, pcode: int, ftb: int):
        self._pcode = pcode
        self._ftb = ftb

    @property
    def pcode(self):
        return self._pcode

    @pcode.setter
    def pcode(self,value):
        self._pcode =int(value)

    @property
    def ftb(self):
        return self._ftb

    @ftb.setter
    def ftb(self, value):
        self._ftb = int(value)


    def encode(self) -> list:
        return list(((self.pcode << 8) + self.ftb).to_bytes(3, byteorder="big", signed=False))

    def decode(self, dtc):
        pass

    @classmethod
    def getInstance(cls, data: list):
        if not len(data) == 3:
            return None
        else:
            return cls((data[0] << 8) + data[1], data[2])


class DTCStatus:
    def __init__(self, status):
        self._warningIndicatorRequested = None
        self._testNotCompletedThisOperationCycle = None
        self._testFailedSinceLastClear = None
        self._testNotCompletedSinceLastClear = None
        self._confirmedDTC = None
        self._pendingDTC = None
        self._testFailed = None
        self._testFailedThisOperationCycle = None
        self._status = None
        self.parser(status)

    def getBit(self, val, index):
        return (val >> (index - 1)) & 0x01

    def parser(self, status):
        self._status = status
        self._testFailed = self.getBit(status, 1)
        self._testFailedThisOperationCycle = self.getBit(status, 2)
        self._pendingDTC = self.getBit(status, 3)
        self._confirmedDTC = self.getBit(status, 4)
        self._testNotCompletedSinceLastClear = self.getBit(status, 5)
        self._testFailedSinceLastClear = self.getBit(status, 6)
        self._testNotCompletedThisOperationCycle = self.getBit(status, 7)
        self._warningIndicatorRequested = self.getBit(status, 8)

    @property
    def status(self):
        return self._status
    @property
    def testFailed(self):
        return self._testFailed
    @property
    def testFailedThisOperationCycle(self):
        return self._testFailedThisOperationCycle

    @property
    def pendingDTC(self):
        return self._pendingDTC

    @property
    def confirmedDTC(self):
        return self._confirmedDTC

    @property
    def testNotCompletedSinceLastClear(self):
        return self._testNotCompletedSinceLastClear

    @property
    def testFailedSinceLastClear(self):
        return self._testFailedSinceLastClear

    @property
    def testNotCompletedThisOperationCycle(self):
        return self._testNotCompletedThisOperationCycle

    @property
    def warningIndicatorRequested(self):
        return self._warningIndicatorRequested

    def encode(self) -> list:
        return [self.status]

    def decode(self, dtc):
        pass

    def check_msk_is_match(self, msk: int):
        return (msk & self._status) >= 1

    @classmethod
    def getInstance(cls, status: list):
        return cls(status[0])


class DTC():
    def __init__(self, pcode, ftb, status):
        self.dtc_val = DTCValue(pcode, ftb)
        self.dtc_st = DTCStatus(status)


@Singleton
class DTCBuffer():
    def __init__(self):
        self.dtc_buffer = [DTC(1, 2, 0xcd), DTC(0x235, 12, 0xfe), DTC(0xd982, 0xf, 0x2e)]

    def add_dtc(self, pcode, ftb, status):
        self.dtc_buffer.append(DTC(pcode, ftb, status))

    def clear_alldtc(self):
        self.dtc_buffer.clear()

    def clear_dtc_by_msk(self, msk: int):
        bu = []
        for i, element in enumerate(self.dtc_buffer):
            if not element.dtc_st.check_msk_is_match(msk):
                bu.append(element)
        self.dtc_buffer = bu

    def get_dtc_by_msk(self, msk: int):
        rr = []
        for i, element in enumerate(self.dtc_buffer):
            if element.dtc_st.check_msk_is_match(msk):
                rr.append(element)
        return rr
