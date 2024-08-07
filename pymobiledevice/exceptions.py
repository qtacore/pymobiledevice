from errno import ENOENT, ENOTDIR

from .constants import AFC_E_UNKNOWN_ERROR, AFC_ERROR_NAMES, AFC_E_OBJECT_NOT_FOUND, AFC_E_OBJECT_IS_DIR

AFC_TO_OS_ERROR_CODES = {
    AFC_E_OBJECT_NOT_FOUND: ENOENT,
    AFC_E_OBJECT_IS_DIR: ENOTDIR,
}


class PyMobileDeviceException(Exception):
    pass

class MuxError(PyMobileDeviceException):
    pass


class ServiceError(PyMobileDeviceException):
    pass


class ConnectionError(PyMobileDeviceException):
    pass
