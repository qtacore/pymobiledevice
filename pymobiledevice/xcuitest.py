## run xcuitest
## https://github.com/alibaba/taobao-iphone-device/blob/main/tidevice/_device.py#L921
import logging
import os
import threading
import time
from distutils.version import LooseVersion

from .dtx import DTXEnum
from .installation_proxy import installation_proxy as InstallationProxy
from .instruments import InstrumentServer
from .house_arrest import HouseArrestService
from .testmanagerd import TestManagerdLockdown
from .bpylist2 import archive, XCTestConfiguration, NSURL, NSUUID
from .dtx_msg import RawObj
from .lockdown import LockdownClient

logging.basicConfig(level=logging.INFO)


class RunXCUITest(threading.Thread):
    def __init__(self, bundle_id, udid=None):
        super().__init__()
        self.udid = udid
        self.bundle_id = bundle_id
        self.quit_event = threading.Event()

    def close(self):
        self.quit_event.set()

    def run(self) -> None:
        def _callback(res):
            logging.info(f"UNDEFINED {res.selector} : {res.auxiliaries}")

        self.lockdown = LockdownClient(udid=self.udid)
        installation = InstallationProxy(lockdown=self.lockdown)
        app_info = installation.find_bundle_id(self.bundle_id)
        sign_identity = app_info.get("SignerIdentity", "")
        logging.info("BundleID: %s", self.bundle_id)
        logging.info("SignIdentity: %r", sign_identity)

        XCODE_VERSION = 29
        session_identifier = NSUUID(bytes=os.urandom(16), version=4)
        tm1 = TestManagerdLockdown(self.lockdown).init()

        channel = "dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface"
        tm1.make_channel(channel)
        if self.lockdown.ios_version > LooseVersion('11.0'):
            tm1.call(channel, "_IDE_initiateControlSessionWithProtocolVersion:", RawObj(XCODE_VERSION))
        tm1.register_selector_callback(DTXEnum.FINISHED, lambda _: self.quit_event.set())
        # tm1.register_undefined_callback(_callback)

        tm2 = TestManagerdLockdown(self.lockdown).init()
        tm2.make_channel(channel)
        tm2.register_selector_callback(DTXEnum.FINISHED, lambda _: self.quit_event.set())
        # tm2.register_undefined_callback(_callback)

        _start_flag = threading.Event()

        def _start_executing(res=None):
            if _start_flag.is_set():
                return
            _start_flag.set()

            logging.info("Start execute test plan with IDE version: %d", XCODE_VERSION)
            tm2._call(False, 0xFFFFFFFF, '_IDE_startExecutingTestPlanWithProtocolVersion:', RawObj(XCODE_VERSION))

        def _show_log_message(res):
            logging.info(f"LogMessage: {res.auxiliaries}")
            if 'Received test runner ready reply' in ''.join(res.auxiliaries):
                _start_executing()

        xctest_content = archive(XCTestConfiguration({
            "testBundleURL": NSURL(None, "file://" + app_info['Path'] + "/PlugIns/XCTestAgent.xctest"),
            "sessionIdentifier": session_identifier,
            "targetApplicationBundleID": app_info['CFBundleIdentifier'],
            "targetApplicationPath": app_info['Path'],
        }))

        def _ready_with_caps_callback(m):
            tm2.send_dtx_message(
                m.channel_code,
                m.identifier,
                0x3,
                xctest_content,
                expects_reply=True
            )

        tm2.register_selector_callback('_XCT_testBundleReadyWithProtocolVersion:minimumVersion:', _start_executing)
        tm2.register_selector_callback('_XCT_logDebugMessage:', _show_log_message)
        tm2.register_selector_callback('_XCT_didFinishExecutingTestPlan', lambda _: self.quit_event.set())
        tm2.register_selector_callback('_XCT_testRunnerReadyWithCapabilities:', _ready_with_caps_callback)

        tm2.call(
            channel,
            '_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:',
            RawObj(session_identifier),
            str(session_identifier) + '-6722-000247F15966B083',
            '/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild',
            RawObj(XCODE_VERSION),
        )

        # launch_wda
        xctest_path = "/tmp/XCTestAgent-" + str(session_identifier).upper() + ".xctestconfiguration"

        fsync = HouseArrestService(self.lockdown)
        fsync.send_command(self.bundle_id)
        for fname in fsync.read_directory("/tmp"):
            if fname.endswith(".xctestconfiguration"):
                logging.debug("remove /tmp/%s", fname)
                fsync.file_remove("/tmp/" + fname)
        fsync.set_file_contents(xctest_path, xctest_content)

        conn = InstrumentServer(self.lockdown).init()
        conn.call('com.apple.instruments.server.services.processcontrol', 'processIdentifierForBundleIdentifier:', self.bundle_id)

        # conn.register_undefined_callback(_callback)
        app_path = app_info['Path']
        app_container = app_info['Container']

        xctestconfiguration_path = app_container + xctest_path
        logging.info("AppPath: %s", app_path)
        logging.info("AppContainer: %s", app_container)

        app_env = {
            'CA_ASSERT_MAIN_THREAD_TRANSACTIONS': '0',
            'CA_DEBUG_TRANSACTIONS': '0',
            'DYLD_FRAMEWORK_PATH': app_path + '/Frameworks:',
            'DYLD_LIBRARY_PATH': app_path + '/Frameworks',
            'NSUnbufferedIO': 'YES',
            'SQLITE_ENABLE_THREAD_ASSERTIONS': '1',
            'WDA_PRODUCT_BUNDLE_IDENTIFIER': '',
            'XCTestConfigurationFilePath': xctestconfiguration_path,
            'XCODE_DBG_XPC_EXCLUSIONS': 'com.apple.dt.xctestSymbolicator',
            'MJPEG_SERVER_PORT': '',
            'USE_PORT': '',
        }
        if self.lockdown.ios_version > LooseVersion('11.0'):
            app_env['DYLD_INSERT_LIBRARIES'] = '/Developer/usr/lib/libMainThreadChecker.dylib'
            app_env['OS_ACTIVITY_DT_MODE'] = 'YES'
        app_options = {'StartSuspendedKey': False}
        if self.lockdown.ios_version > LooseVersion('12.0'):
            app_options['ActivateSuspended'] = True

        app_args = [
            '-NSTreatUnknownArgumentsAsOpen', 'NO',
            '-ApplePersistenceIgnoreState', 'YES'
        ]

        identifier = "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:"

        pid = conn.call('com.apple.instruments.server.services.processcontrol', identifier,
                        app_path, self.bundle_id, app_env, app_args, app_options).selector
        if not isinstance(pid, int):
            logging.error(f"Launch failed: {pid}")
            raise Exception("Launch failed")

        logging.info(f"Launch {self.bundle_id} pid: {pid}")

        conn.call('com.apple.instruments.server.services.processcontrol', "startObservingPid:", RawObj(pid))

        def _new_callback(m):
            if m is None:
                print("WebDriverAgentRunner quitted")
                return
            if m.flags == 0x02:
                method, args = m.result
                if method == 'outputReceived:fromProcess:atTime:':
                    # logger.info("Output: %s", args[0].strip())
                    print("logProcess: %s", args[0].rstrip())
                    # XCTestOutputBarrier is just ouput separators, no need to
                    # print them in the logs.
                    if args[0].rstrip() != 'XCTestOutputBarrier':
                        print('%s', args[0].rstrip())
                    # In low iOS versions, 'Using singleton test manager' may not be printed... mark wda launch status = True if server url has been printed
                    if "ServerURLHere" in args[0]:
                        print("%s", args[0].rstrip())
                        print("WebDriverAgent start successfully")

        conn.register_selector_callback(DTXEnum.NOTIFICATION, _new_callback)
        conn.register_selector_callback("_XCT_logDebugMessage:", _show_log_message)

        print("before quit event callback")
        if self.quit_event:
            conn.register_selector_callback(DTXEnum.FINISHED, lambda _: self.quit_event.set())

        print("preparing sending")
        if self.lockdown.ios_version >= LooseVersion('12.0'):
            identifier = '_IDE_authorizeTestSessionWithProcessID:'
            result = tm1.call(
                'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface',
                identifier,
                RawObj(pid)).selector
            logging.info("_IDE_authorizeTestSessionWithProcessID: %s", result)
        else:
            identifier = '_IDE_initiateControlSessionForTestProcessID:protocolVersion:'
            result = tm1.call(
                'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface',
                identifier,
                RawObj(pid), RawObj(XCODE_VERSION)).selector
            logging.info("_IDE_authorizeTestSessionWithProcessID: %s", result)
        print("sending finished")

        while not self.quit_event.wait(.1):
            pass
        logging.warning("xctrunner quited")
        conn.stop()
        tm2.stop()
        tm1.stop()


if __name__ == '__main__':
    bundle_id = 'com.tencent.testsolar.xctagent.xctrunner.xctrunner'
    xcuitest = RunXCUITest(bundle_id)
    xcuitest.start()
    time.sleep(100)
    xcuitest.close()
