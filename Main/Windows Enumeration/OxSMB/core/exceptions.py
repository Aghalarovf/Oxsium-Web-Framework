class OxSMBError(Exception):
    pass


class TransportError(OxSMBError):
    pass


class ConnectionTimeout(TransportError):
    pass


class SMBNegotiateError(OxSMBError):
    pass


class SMBSessionSetupError(OxSMBError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class SMBTreeConnectError(OxSMBError):
    pass


class SMBCreateError(OxSMBError):
    pass


class SMBReadWriteError(OxSMBError):
    pass


class AuthError(OxSMBError):
    pass


class NTLMError(AuthError):
    pass


class RPCBindError(OxSMBError):
    pass


class RPCCallError(OxSMBError):
    pass


class NDRError(OxSMBError):
    pass


class PacketParseError(OxSMBError):
    pass


class ModuleExecutionError(OxSMBError):
    pass


class PluginError(OxSMBError):
    pass


class PluginLoadError(PluginError):
    pass


class ConfigError(OxSMBError):
    pass
