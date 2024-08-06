"""

"""
import logging

from .afc import AFCClient, AFCShell
from .lockdown import LockdownClient


class HouseArrestService(AFCClient):
    SERVICE_NAME = "com.apple.mobile.house_arrest"
    RSD_SERVICE_NAME = 'com.apple.mobile.house_arrest.shim.remote'

    def __init__(self, lockdown=None, udid=None, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.lockdown = lockdown or LockdownClient(udid=udid)
        SERVICE_NAME = self.SERVICE_NAME

        super(HouseArrestService, self).__init__(self.lockdown, SERVICE_NAME)

    def stop_session(self):
        self.logger.info("Disconecting...")
        self.service.close()

    def send_command(self, applicationId, cmd="VendContainer"):
        self.service.sendPlist({"Command": cmd, "Identifier": applicationId})
        res = self.service.recvPlist()
        if res.get("Error"):
            self.logger.error("%s : %s", applicationId, res.get("Error"))
            return False
        else:
            return True

    def shell(self, applicationId, cmd="VendContainer"):
        res = self.send_command(applicationId, cmd)
        if res:
            AFCShell(client=self).cmdloop()


if __name__ == '__main__':
    HouseArrestService().shell('cn.rongcloud.rce.autotest.xctrunner')
