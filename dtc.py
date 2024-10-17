from uds_addtion import Singleton


class DTCValue:
    def __init__(self, pcode: int, ftb: int):
        self.pcode = pcode
        self.ftb = ftb

    def encode(self) -> list:
        return list(((self.pcode << 8) + self.ftb).to_bytes(3, byteorder="big", signed=False))

    def decode(self, dtc):
        pass

    def getPcode(self):
        return self.pcode

    def getFtb(self):
        return self.ftb

    @classmethod
    def getInstance(cls, data: list):
        if not len(data) == 3:
            return None
        else:
            return cls((data[0] << 8) + data[1], data[2])


class DTCStatus:
    status = 0
    testFailed = 0
    testFailedThisOperationCycle = 0
    pendingDTC = 0
    confirmedDTC = 0
    testNotCompletedSinceLastClear = 0
    testFailedSinceLastClear = 0
    testNotCompletedThisOperationCycle = 0
    warningIndicatorRequested = 0

    def __init__(self, status):
        self.parser(status)

    def getBit(self, val, index):
        return (val >> (index - 1)) & 0x01

    def parser(self, status):
        self.status = status
        self.testFailed = self.getBit(status, 1)
        self.testFailedThisOperationCycle = self.getBit(status, 2)
        self.pendingDTC = self.getBit(status, 3)
        self.confirmedDTC = self.getBit(status, 4)
        self.testNotCompletedSinceLastClear = self.getBit(status, 5)
        self.testFailedSinceLastClear = self.getBit(status, 6)
        self.testNotCompletedThisOperationCycle = self.getBit(status, 7)
        self.warningIndicatorRequested = self.getBit(status, 8)

    def encode(self) -> list:
        return [self.status]

    def decode(self, dtc):
        pass

    def check_msk_is_match(self, msk: int):
        return (msk & self.status) >= 1

    @classmethod
    def getInstance(cls, status: list):
        return cls(status[0])


class DTC():
    def __init__(self, pcode, ftb, status):
        self.dtc_val = DTCValue(pcode, ftb)
        self.dtc_st = DTCStatus(status)


@Singleton
class DTCBuffer():
    dtc_buffer = []

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
