import inspect


class UDSResponseCode:
    PositiveResponse = 0
    GeneralReject = 0x10
    ServiceNotSupported = 0x11
    SubFunctionNotSupported = 0x12
    IncorrectMessageLengthOrInvalidFormat = 0x13
    ResponseTooLong = 0x14
    BusyRepeatRequest = 0x21
    ConditionsNotCorrect = 0x22
    RequestSequenceError = 0x24
    NoResponseFromSubnetComponent = 0x25
    FailurePreventsExecutionOfRequestedAction = 0x26
    RequestOutOfRange = 0x31
    SecurityAccessDenied = 0x33
    AuthenticationRequired = 0x34
    InvalidKey = 0x35
    ExceedNumberOfAttempts = 0x36
    RequiredTimeDelayNotExpired = 0x37
    SecureDataTransmissionRequired = 0x38
    SecureDataTransmissionNotAllowed = 0x39
    SecureDataVerificationFailed = 0x3A
    CertificateVerificationFailed_InvalidTimePeriod = 0x50
    CertificateVerificationFailed_InvalidSignature = 0x51
    CertificateVerificationFailed_InvalidChainOfTrust = 0x52
    CertificateVerificationFailed_InvalidType = 0x53
    CertificateVerificationFailed_InvalidFormat = 0x54
    CertificateVerificationFailed_InvalidContent = 0x55
    CertificateVerificationFailed_InvalidScope = 0x56
    CertificateVerificationFailed_InvalidCertificate = 0x57
    OwnershipVerificationFailed = 0x58
    ChallengeCalculationFailed = 0x59
    SettingAccessRightsFailed = 0x5A
    SessionKeyCreationDerivationFailed = 0x5B
    ConfigurationDataUsageFailed = 0x5C
    DeAuthenticationFailed = 0x5D
    UploadDownloadNotAccepted = 0x70
    TransferDataSuspended = 0x71
    GeneralProgrammingFailure = 0x72
    WrongBlockSequenceCounter = 0x73
    RequestCorrectlyReceived_ResponsePending = 0x78
    SubFunctionNotSupportedInActiveSession = 0x7E
    ServiceNotSupportedInActiveSession = 0x7F
    RpmTooHigh = 0x81
    RpmTooLow = 0x82
    EngineIsRunning = 0x83
    EngineIsNotRunning = 0x84
    EngineRunTimeTooLow = 0x85
    TemperatureTooHigh = 0x86
    TemperatureTooLow = 0x87
    VehicleSpeedTooHigh = 0x88
    VehicleSpeedTooLow = 0x89
    ThrottlePedalTooHigh = 0x8A
    ThrottlePedalTooLow = 0x8B
    TransmissionRangeNotInNeutral = 0x8C
    TransmissionRangeNotInGear = 0x8D
    BrakeSwitchNotClosed = 0x8F
    ShifterLeverNotInPark = 0x90
    TorqueConverterClutchLocked = 0x91
    VoltageTooHigh = 0x92
    VoltageTooLow = 0x93
    ResourceTemporarilyNotAvailable = 0x94

    # Defined by ISO-15764. Offset of 0x38 is defined within UDS standard (ISO-14229)
    GeneralSecurityViolation = 0x38 + 0
    SecuredModeRequested = 0x38 + 1
    InsufficientProtection = 0x38 + 2
    TerminationWithSignatureRequested = 0x38 + 3
    AccessDenied = 0x38 + 4
    VersionNotSupported = 0x38 + 5
    SecuredLinkNotSupported = 0x38 + 6
    CertificateNotAvailable = 0x38 + 7
    AuditTrailInformationNotAvailable = 0x38 + 8

    # Returns the name of the response code as a string
    @classmethod
    def get_name(cls, given_id: int) -> str:
        if given_id is None:
            return ""

        for member in inspect.getmembers(cls):
            if isinstance(member[1], int):
                if member[1] == given_id:
                    return member[0]
        return str(given_id)

    # Tells if a code is a negative code
    @classmethod
    def is_negative(cls, given_id: int) -> bool:
        if given_id in [None, cls.PositiveResponse]:
            return False

        for member in inspect.getmembers(cls):
            if isinstance(member[1], int):
                if member[1] == given_id:
                    return True
        return False
