from packaging.version import Version

from .dtx import DTXServer
from pymobiledevice.lockdown import LockdownClient


class InstrumentServer(DTXServer):
    SERVICE_NAME = 'com.apple.instruments.remoteserver.DVTSecureSocketProxy'
    OLD_SERVICE_NAME = 'com.apple.instruments.remoteserver'
    RSD_SERVICE_NAME = 'com.apple.instruments.dtservicehub'

    def __init__(self, lockdown=None, udid=None):
        super().__init__()
        self.lockdown = lockdown or LockdownClient(udid=udid)

    def init(self, cli=None):
        if not cli:
            if Version(self.lockdown.ios_version) >= Version('14.0'):
                cli = self.lockdown.startService(self.SERVICE_NAME)
            else:
                cli = self.lockdown.startService(self.OLD_SERVICE_NAME)
                if hasattr(cli.sock, '_sslobj'):
                    cli.sock._sslobj = None  # remoteserver 协议配对成功之后，需要关闭 ssl 协议通道，使用明文传输
        return super().init(cli)


if __name__ == '__main__':
    conn = InstrumentServer().init()
    conn.call(
        'com.apple.instruments.server.services.processcontrol',
        'processIdentifierForBundleIdentifier:',
        'com.tencent.testsolar.xctagent.xctrunner.xctrunner',
    )
    conn.stop()
