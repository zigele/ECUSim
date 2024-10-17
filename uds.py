import logging
import struct
from abc import ABC
from enum import Enum
from typing import List

from did import DIDList
from dtc import DTCBuffer
from uds_addtion import Singleton
from uds_response_code import UDSResponseCode

logger = logging.getLogger("app")


class UDSService(Enum):
    DiagnosticSessionControl = 0x10
    ECUReset = 0x11
    SecurityAccess = 0x27
    CommunicationControl = 0x28
    TesterPresent = 0x3e
    AccessTimingParameter = 0x83
    SecuredDataTransmission = 0x84
    ControlDTCSetting = 0x85
    ResponseOnEvent = 0x86
    LinkControl = 0x87
    ReadDataByIdentifier = 0x22
    ReadMemoryByAddress = 0x23
    ReadScalingDataByIdentifier = 0x24
    ReadDataByPeriodicIdentifier = 0x2a
    DynamicallyDefineDataIdentifier = 0x2c
    WriteDataByIdentifier = 0x2e
    WriteMemoryByAddress = 0x3d
    ClearDiagnosticInformation = 0x14
    ReadDTCInformation = 0x19
    InputOutputControlByIdentifier = 0x2f
    RoutineControl = 0x31
    RequestDownload = 0x34
    RequestUpload = 0x35
    TransferData = 0x36
    RequestTransferExit = 0x37

    @classmethod
    def get_name(cls, key: int) -> str:
        if key in cls._value2member_map_:
            return cls(key).name
        else:
            return None


class BaseService(ABC):
    always_valid_negative_response = [
        UDSResponseCode.GeneralReject,
        UDSResponseCode.ServiceNotSupported,
        UDSResponseCode.ResponseTooLong,
        UDSResponseCode.BusyRepeatRequest,
        UDSResponseCode.NoResponseFromSubnetComponent,
        UDSResponseCode.FailurePreventsExecutionOfRequestedAction,
        UDSResponseCode.SecurityAccessDenied,
        # ISO-14229:2006 Table A.1:  "Besides the mandatory use of this negative response code as specified in the applicable services within ISO 14229, this negative response code can also be used for any case where security is required and is not yet granted to perform the required service."
        UDSResponseCode.AuthenticationRequired,  # ISO-14229:2020 Figure 5 - General server response behaviour
        UDSResponseCode.SecureDataTransmissionRequired,  # ISO-14229:2020 Figure 5 - General server response behaviour
        UDSResponseCode.SecureDataTransmissionNotAllowed,  # ISO-14229:2020 Figure 5 - General server response behaviour
        UDSResponseCode.RequestCorrectlyReceived_ResponsePending,
        UDSResponseCode.ServiceNotSupportedInActiveSession,
        UDSResponseCode.ResourceTemporarilyNotAvailable
    ]
    _neg_response = 0x7f
    _sid: int
    _sub_func: bool = False
    supported_negative_response: List[int]

    def request_id(self) -> int:
        return self._sid

    def response_id(self) -> int:
        return self._sid + 0x40

    def is_valid_negative_response(self, negative_code: UDSResponseCode):
        if negative_code in self.always_valid_negative_response:
            return True
        elif negative_code in self.supported_negative_response:
            return True
        else:
            return False

    def make_neg_response(self, negative_code: UDSResponseCode) -> List:
        if not self.is_valid_negative_response(negative_code):
            raise Exception("negative_code is not support!")
        return [self._neg_response, self._sid, negative_code]

    def make_pos_response(self, *args, **kwargs) -> List:
        pass

    def process(self, data: list):
        pass

    def is_suppressPosRspMsgIndicationBit(self, val):
        return (((val & 0xff) >> 7) == 0)


class DiagnosticSessionControl(BaseService):
    _sid = 0x10
    _sub_func = True

    class DiagnosticSessionType(Enum):
        ISOSAEReserved = 0
        DefaultSession = 1
        ProgrammingSession = 2
        ExtendedDiagnosticSession = 3
        SafetySystemDiagnosticSession = 4

    supported_negative_response = [UDSResponseCode.SubFunctionNotSupported,
                                   UDSResponseCode.IncorrectMessageLengthOrInvalidFormat,
                                   UDSResponseCode.ConditionsNotCorrect,
                                   UDSResponseCode.RequestOutOfRange
                                   ]

    def make_pos_response(self, session: DiagnosticSessionType, p2_server_max: float,
                          p2_star_server_max: float) -> List:
        res = struct.pack('>HH', int(p2_server_max), int(p2_star_server_max / 10))
        return [self.response_id(), session] + list(res)

    def process(self, data: list) -> list:
        req_sid, session_type, *reserved = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ECUReset.")
        if not session_type in self.DiagnosticSessionType._value2member_map_:
            logger.info(f"the diag session type {session_type} of DiagnosticSessionControl is not define.")
            r = self.make_neg_response(UDSResponseCode.RequestOutOfRange)
            logger.info(f'DiagnosticSessionControl make neg respnse {r}')
            return r
        if self.is_suppressPosRspMsgIndicationBit(session_type):
            r = self.make_pos_response(session_type, 5000, 2000)
            logger.info(f'DiagnosticSessionControl make pos respnse {r}')
            return r
        else:
            return None


class ECUReset(BaseService):
    _sid = 0x11
    supported_negative_response = [UDSResponseCode.RequestOutOfRange]
    _sub_func = True

    class ResetType(Enum):
        ISOSAEReserved = 0
        hardReset = 1
        keyOffOnReset = 2
        softReset = 3
        enableRapidPowerShutDown = 4
        disableRapidPowerShutDown = 5

    def make_pos_response(self, type, power_down_time=None) -> List:
        if not power_down_time is None:
            return [self.response_id(), type, power_down_time]
        else:
            return [self.response_id(), type]

    def process(self, data: list) -> list:
        req_sid, reset_type, *reserved = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ECUReset.")

        if not reset_type in self.ResetType._value2member_map_:
            logger.info(f"the reset type {reset_type} of ECUReset is not define.")

        if self.is_suppressPosRspMsgIndicationBit(reset_type):
            if reset_type == self.ResetType.enableRapidPowerShutDown.value:
                r = self.make_pos_response(reset_type, 0x3b)
                logger.info(f'ECUReset make pos respnse {r}')
                return r
            else:
                r = self.make_pos_response(reset_type)
                logger.info(f'ECUReset make pos respnse {r}')
                return r
        else:
            return None


class SecurityAccess(BaseService):
    _sid = 0x27
    _sub_func = True
    _unlock_level = 0

    supported_negative_response = [UDSResponseCode.RequestOutOfRange]

    class SeedSYm(Enum):
        Level_1 = 1
        Level_2 = 3
        Level_3 = 5
        Level_4 = 7

    class KeySym(Enum):
        Level_1 = 2
        Level_2 = 4
        Level_3 = 6
        Level_4 = 8

    def make_pos_response(self, *args, **kwargs) -> List:
        pass

    def get_seed(self, level: SeedSYm) -> list:
        self._unlock_level = level
        return [self.response_id(), level, 1, 2, 3, 4]

    def unlock(self) -> bool:
        return [self.response_id(), self._unlock_level + 1]

    def process(self, data: list):
        req_sid, security_access_type, *reserved = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ECUReset.")

        if security_access_type in self.SeedSYm._value2member_map_:
            r = self.get_seed(security_access_type)
            logger.info(f'DiagnosticSessionControl make pos respnse {r}')
            if self.is_suppressPosRspMsgIndicationBit(security_access_type):
                return r
            else:
                return None
        elif security_access_type in self.KeySym._value2member_map_:
            r = self.unlock()
            logger.info(f'DiagnosticSessionControl make pos respnse {r}')
            if self.is_suppressPosRspMsgIndicationBit(security_access_type):
                return r
            else:
                return None
        else:
            logger.info(f"the diag session type {security_access_type} of DiagnosticSessionControl is not define.")
            r = self.make_neg_response(UDSResponseCode.RequestOutOfRange)
            logger.info(f'DiagnosticSessionControl make neg respnse {r}')
            return r


class CommunicationControl(BaseService):
    _sid = 0x28
    _sub_func = True
    supported_negative_response = [UDSResponseCode.RequestOutOfRange]

    class ControlType(Enum):
        EnableRxAndTx = 0
        EnableRxAndDisableTx = 1
        DisableRxAndEnableTx = 2
        DisableRxAndTx = 3

    def make_pos_response(self, control_type) -> List:
        return [self.response_id(), control_type]

    def process(self, data: list):
        req_sid, control_type, communication_type, *reserved = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ECUReset.")
        if not control_type in self.ControlType._value2member_map_:
            logger.info(f"the diag session type {control_type} of DiagnosticSessionControl is not define.")
            r = self.make_neg_response(UDSResponseCode.RequestOutOfRange)
            logger.info(f'DiagnosticSessionControl make neg respnse {r}')
            return r

        if self.is_suppressPosRspMsgIndicationBit(control_type):
            return self.make_pos_response(control_type)
        else:
            return None


class TesterPresent(BaseService):
    _sid = 0x3E
    _sub_func = True
    supported_negative_response = [UDSResponseCode.RequestOutOfRange]

    def make_pos_response(self, *args, **kwargs) -> List:
        return [self.response_id(), 0x00]

    def process(self, data: list):
        req_sid, zeroSubFunction, *servered = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ECUReset.")
        if self.is_suppressPosRspMsgIndicationBit(zeroSubFunction):
            return self.make_pos_response()
        else:
            return None


class ControlDTCSetting(BaseService):
    _sid = 0x85
    _sub_func = True
    supported_negative_response = [UDSResponseCode.RequestOutOfRange]

    class DTCSettingType(Enum):
        ISOSAEReserved = 0
        On = 1
        Off = 2

    def make_pos_response(self, dtc_setting_type) -> List:
        return [self.response_id(), dtc_setting_type]

    def process(self, data: list):
        req_sid, dtc_setting_type, *servered = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ECUReset.")
        if not dtc_setting_type in self.DTCSettingType._value2member_map_:
            r = self.make_neg_response(UDSResponseCode.RequestOutOfRange)
            logger.info(f'ControlDTCSetting make neg respnse {r}')
            return r
        if self.is_suppressPosRspMsgIndicationBit(dtc_setting_type):
            return self.make_pos_response(dtc_setting_type)
        else:
            return None


class ReadDataByIdentifier(BaseService):
    _sid = 0x22
    _sub_func = False
    supported_negative_response = [UDSResponseCode.RequestOutOfRange]

    def make_pos_response(self, res: list) -> List:
        return [self.response_id()] + res

    def process(self, data: list):
        req_sid, *did_list = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ReadDataByIdentifier.")

        r = self.make_neg_response(UDSResponseCode.RequestOutOfRange)
        if not len(did_list) % 2 == 0:
            logger.info(f'ReadDataByIdentifier make neg respnse 1{r}')
            return r
        if not len(did_list) >= 2:
            logger.info(f'ReadDataByIdentifier make neg respnse {r}')
            return r

        did_num = int(len(did_list) / 2)
        did_li = struct.unpack((">" + "H" * did_num), bytes(did_list))

        for d in did_li:
            if not d in DIDList.dict.keys():
                logger.info(f'ControlDTCSetting make neg respnse 2{r}')
                return r
        for d in did_li:
            if not d in DIDList.value.keys():
                logger.info(f'ControlDTCSetting make neg respnse 3{r}')
                return r
        res = []
        for d in did_li:
            if not d is None:
                res += [(d >> 8) & 0xff, d & 0xff]
                res = res + list(DIDList.dict[d].encode(DIDList.value[d]))

        return self.make_pos_response(res)


class WriteDataByIdentifier(BaseService):
    _sid = 0x2E
    _sub_func = False
    supported_negative_response = [UDSResponseCode.RequestOutOfRange]

    def make_pos_response(self, res: list) -> List:
        return [self.response_id()] + res

    def process(self, data: list):
        req_sid, *did_list = data
        r = self.make_neg_response(UDSResponseCode.RequestOutOfRange)
        if not req_sid == self._sid:
            raise Exception("the data is not belong WriteDataByIdentifier.")
        if not len(did_list) > 2:
            logger.info(f'WriteDataByIdentifier make neg respnse {r}')
            return r

        did_w = (did_list[0] << 8) + did_list[1]
        if not did_w in DIDList.dict.keys():
            logger.info(f'WriteDataByIdentifier make neg respnse 1 {r}')
            return r
        else:
            did_len = DIDList.dict[did_w].did_len
            if len(did_list) < (did_len + 2):
                logger.info(f'WriteDataByIdentifier make neg respnse 2 {r}')
                return r
            else:
                DIDList.value[did_w] = DIDList.dict[did_w].decode((did_list[2:2 + did_len]))
        return self.make_pos_response(did_list[0:2])


class ClearDiagnosticInformation(BaseService):
    _sid = 0x14
    _sub_func = False

    def make_pos_response(self, *args, **kwargs) -> List:
        return [self.response_id()]

    def process(self, data: list):
        if len(data) < 4:
            return self.make_neg_response(UDSResponseCode.GeneralReject)
        req_sid, GODTC_HB, GODTC_MB, GODTC_LB, *reseved = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ClearDiagnosticInformation.")
        if GODTC_HB == 0xff and GODTC_LB == 0xff and GODTC_MB == 0xff:
            d = DTCBuffer()
            d.clear_alldtc()
        return self.make_pos_response()


class ReadDTCInformation(BaseService):
    _sid = 0x19
    _sub_func = True
    _DTCStatusAvailabilityMask = 0xff

    class SubFun(Enum):
        reportNumberOfDTCByStatusMask = 1
        reportDTCByStatusMask = 2
        reportMirrorMemoryDTCByStatusMask = 0xf
        reportNumberOfMirrorMemoryDTCByStatusMask = 0x11
        reportNumberOfEmissionsRelatedOBDDTCByStatusMask = 0x12
        reportEmissionsRelatedOBDDTCByStatusMask = 0x13
        reportDTCSnapshotIdentification = 0x3
        reportDTCSnapshotRecordByDTCNumber = 0x4
        reportDTCSnapshotRecordByRecordNumber = 0x5
        reportDTCExtendedDataRecordByDTCNumber = 0x6
        reportMirrorMemoryDTCExtendedDataRecordByDTCNumber = 0x10
        reportNumberOfDTCBySeverityMaskRecord = 0x7
        reportDTCBySeverityMaskRecord = 0x8
        reportSeverityInformationOfDTC = 0x9
        reportSupportedDTC = 0xa
        reportFirstTestFailedDTC = 0xb
        reportFirstConfirmedDTC = 0xc
        reportMostRecentTestFailedDTC = 0xd
        reportMostRecentConfirmedDTC = 0xe
        reportDTCFaultDetectionCounter = 0x14
        reportDTCWithPermanentStatus = 0x15

    def make_pos_response(self, *args, **kwargs) -> List:
        return [self.response_id(), ]

    def process(self, data: list):
        if len(data) < 3:
            return self.make_neg_response(UDSResponseCode.GeneralReject)
        req_sid, subfunc, *reseved = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ReadDTCInformation.")
        if subfunc == self.SubFun.reportDTCByStatusMask.value:
            dtc_msk, *notused = reseved
            d = DTCBuffer()
            res = d.get_dtc_by_msk(dtc_msk)
            print(res)
        else:
            return self.make_neg_response(UDSResponseCode.RequestOutOfRange)


@Singleton
class EOL():
    eol_active_status = False
    eol_start_address = 0
    eol_transferred_size = 0
    eol_rev_count = 0
    eol_rev_block_count = 0
    maxNumberOfBlockLength = 0x0fff
    rev_buffer = []
    erase_flash_start_address = 0
    erase_flash_size = 0

    def reset(self):
        self.eol_active_status = False
        self.eol_start_address = 0
        self.eol_size_of_data = 0
        self.eol_transferred_size = 0
        self.eol_rev_count = 0
        self.eol_rev_block_count = 0
        self.maxNumberOfBlockLength = 0x0fff
        self.rev_buffer = []
        self.erase_flash_start_address = 0
        self.erase_flash_size = 0


class RoutineControl(BaseService):
    _sid = 0x31
    _sub_func = True
    supported_negative_response = []
    eol = EOL()

    class RoutineStatus(Enum):
        Succeed = 0x1
        Failed = 0xff

    class RoutineControlType(Enum):
        StartRoutine = 1
        StopRoutine = 2
        RequestRoutineResults = 3

    class RoutineIdentifier(Enum):
        EraseFlash = 0x1122
        CheckMemory = 0x3344

    def make_pos_response(self, addition: list) -> List:
        return [self.response_id()] + addition

    def process(self, data: list):
        req_sid, subfunc, routineIdHB, routineIdLB, *routineControlOptionRecord = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong ReadDTCInformation.")
        if subfunc == self.RoutineControlType.StartRoutine.value:
            if ((routineIdHB << 8) + routineIdLB) == self.RoutineIdentifier.EraseFlash.value:
                self.eol.reset()
                self.eol.erase_flash_start_address = (routineControlOptionRecord[0] << 24) + (
                            routineControlOptionRecord[1] << 16) + (routineControlOptionRecord[2] << 8) + (
                                                     routineControlOptionRecord[3])
                self.eol.erase_flash_size = (routineControlOptionRecord[4] << 24) + (
                            routineControlOptionRecord[5] << 16) + (routineControlOptionRecord[6] << 8) + (
                                            routineControlOptionRecord[7])
                return self.make_pos_response([self.RoutineControlType.StartRoutine.value, routineIdHB, routineIdLB,
                                               self.RoutineStatus.Succeed.value])
            elif ((routineIdHB << 8) + routineIdLB) == self.RoutineIdentifier.CheckMemory.value:
                return self.make_pos_response([self.RoutineControlType.StartRoutine.value, routineIdHB, routineIdLB,
                                               self.RoutineStatus.Succeed.value])
            else:
                pass


class RequestDownload(BaseService):
    _sid = 0x34
    _sub_func = False
    memoryAddressSize = 0
    memorySize = 0
    lengthFormatIdentifier = 0x20
    e = EOL()
    supported_negative_response = [UDSResponseCode.RequestSequenceError, UDSResponseCode.TransferDataSuspended]

    def make_pos_response(self, dataFormatIdentifier) -> List:
        return [self.response_id(), self.lengthFormatIdentifier, self.e.maxNumberOfBlockLength >> 8,
                self.e.maxNumberOfBlockLength & 0xff]

    def process(self, data: list):
        if len(data) < 3:
            self.eol.reset()
            return self.make_neg_response(UDSResponseCode.GeneralReject)
        req_sid, dataFormatIdentifier, addressAndLengthFormatIdentifier, *reseved = data
        self.memoryAddressSize = (addressAndLengthFormatIdentifier & 0xf)
        self.memorySize = ((addressAndLengthFormatIdentifier & 0xff) >> 4)
        if len(data) < (3 + self.memoryAddressSize + self.memorySize):
            self.eol.reset()
            return self.make_neg_response(UDSResponseCode.GeneralReject)
        n = 0
        m = 0
        for i in range(self.memoryAddressSize):
            n = n + (reseved[i] << ((self.memoryAddressSize - i - 1) * 8))
        for i in range(self.memorySize):
            m = m + (reseved[i + self.memoryAddressSize] << ((self.memorySize - i - 1) * 8))
        self.e.eol_active_status = True
        self.e.eol_start_address = n
        self.e.eol_transferred_size = m
        return self.make_pos_response(dataFormatIdentifier)


class RequestUpload(BaseService):
    _sid = 0x35
    _sub_func = True
    supported_negative_response = [UDSResponseCode.RequestSequenceError, UDSResponseCode.TransferDataSuspended]

    def make_pos_response(self, *args, **kwargs) -> List:
        pass

    def process(self, data: list):
        return self.make_neg_response(UDSResponseCode.GeneralReject)


class TransferData(BaseService):
    _sid = 0x36
    _sub_func = True
    blockSequenceCounter = 0
    eol = EOL()
    supported_negative_response = [UDSResponseCode.RequestSequenceError, UDSResponseCode.TransferDataSuspended]

    def make_pos_response(self, blockCount) -> List:
        return [self.response_id(), blockCount]

    def process(self, data: list):
        req_sid, blockSequenceCounter, *reversed = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong TransferData.")
        if self.eol.eol_active_status:
            if not ((self.eol.eol_rev_block_count + 1) == blockSequenceCounter):
                self.eol.reset()
                return self.make_neg_response(UDSResponseCode.RequestSequenceError)

        if (2 + len(reversed)) <= self.eol.maxNumberOfBlockLength:
            self.eol.rev_buffer.extend(reversed)
            self.eol.eol_rev_count = self.eol.eol_rev_count + len(reversed)
            self.eol.eol_rev_block_count += 1
            print(self.eol.eol_rev_count)
            print(self.eol.eol_rev_block_count)
            if self.eol.eol_rev_block_count == 0xff:
                self.eol.eol_rev_block_count = -1  # why this value will be start with zero after catch 0xff。
            return self.make_pos_response(blockSequenceCounter)


class RequestTransferExit(BaseService):
    _sid = 0x37
    _sub_func = False
    eol = EOL()
    supported_negative_response = [UDSResponseCode.IncorrectMessageLengthOrInvalidFormat]

    def make_pos_response(self, *args, **kwargs) -> List:
        return [self.response_id()]

    def process(self, data: list):
        req_sid, *reserved = data
        if not req_sid == self._sid:
            raise Exception("the data is not belong RequestTransferExit.")
        return self.make_pos_response()
