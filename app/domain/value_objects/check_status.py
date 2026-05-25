from enum import Enum


class CheckStatus(str, Enum):
    OK = "OK"
    WARNING = "WARNING"
    FAILED = "FAILED"
    ERROR = "ERROR"
    NOT_SUPPORTED = "NOT_SUPPORTED"
