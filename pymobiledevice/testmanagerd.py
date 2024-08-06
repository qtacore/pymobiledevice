from packaging.version import Version

from .dtx import DTXServer
from pymobiledevice.lockdown import LockdownClient


class TestManagerdLockdown(DTXServer):
    SERVICE_NAME = 'com.apple.testmanagerd.lockdown.secure'
    OLD_SERVICE_NAME = 'com.apple.testmanagerd.lockdown'
    RSD_SERVICE_NAME = 'com.apple.dt.testmanagerd.remote'

    def __init__(self, lockdown=None, udid=None, network=None):
        super().__init__()
        self.lockdown = lockdown or LockdownClient(udid=udid, network=network)

    def init(self, cli=None):
        if not cli:
            if Version(self.lockdown.ios_version) >= Version('14.0'):
                cli = self.lockdown.startService("com.apple.testmanagerd.lockdown.secure")
            else:
                cli = self.lockdown.startService("com.apple.testmanagerd.lockdown")
                if hasattr(cli.sock, '_sslobj'):
                    cli.sock._sslobj = None  # remoteserver 协议配对成功之后，需要关闭 ssl 协议通道，使用明文传输
        return super().init(cli)
