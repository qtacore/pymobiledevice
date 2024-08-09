## run xcuitest
## https://github.com/alibaba/taobao-iphone-device/blob/main/tidevice/_device.py#L921
from __future__ import print_function
import logging
import threading
import uuid
import typing
import fnmatch
import attr

from .util import bplist
from .installation_proxy import installation_proxy as InstallationProxy
from .house_arrest import HouseArrestService
from .lockdown import LockdownClient
from .instruments import DTXService
from .instruments import (
    AUXMessageBuffer,
    DTXPayload, DTXService,
    Event, ServiceInstruments)
from .exceptions import MuxError
from .installation_proxy import installation_proxy as InstallationProxy


_T = typing.TypeVar("_T")

logger = logging.getLogger("pymobiledevice.xcuitest")
logger.setLevel(level=logging.DEBUG)


def alias_field(name):
    """
    Args:
        name (str): name
    Returns:
        attr.ib
    """
    return attr.ib(metadata={"alias": name})


class _BaseInfo(object):
    def _asdict(self):
        """ for simplejson
        Returns:
            dict
        """
        return attr.asdict(self)

    @classmethod
    def from_json(cls, data):
        """
        Args:
            cls (_T):
            data (dict):
        Returns:
            _T
        """
        kwargs = {}
        for field in attr.fields(cls):
            possible_names = [field.name]
            if "alias" in field.metadata:
                possible_names.append(field.metadata["alias"])
            for name in possible_names:
                if name in data:
                    value = data[name]
                    if field.type != type(value):
                        value = field.type(value)
                    kwargs[field.name] = value
                    break
        return cls(**kwargs)

    def __repr__(self):
        """
        Returns:
            str
        """
        attrs = []
        for k, v in self.__dict__.items():
            attrs.append("{}={!r}".format(k, v))
        return "<{} ".format(self.__class__.__name__) + ", ".join(attrs) + ">"


@attr.s(frozen=True)
class XCTestResult(_BaseInfo):
    """Representing the XCTest result printed at the end of test.

    At the end of an XCTest, the test process will print following information:

        Test Suite 'MoblySignInTests' passed at 2023-09-03 16:35:39.214.
                Executed 1 test, with 0 failures (0 unexpected) in 3.850 (3.864) seconds
        Test Suite 'MoblySignInTests.xctest' passed at 2023-09-03 16:35:39.216.
                 Executed 1 test, with 0 failures (0 unexpected) in 3.850 (3.866) seconds
        Test Suite 'Selected tests' passed at 2023-09-03 16:35:39.217.
                 Executed 1 test, with 0 failures (0 unexpected) in 3.850 (3.869) seconds
    """

    MESSAGE = (
        "Test Suite '{test_suite_name}' passed at {end_time}.\n"
        "\t Executed {run_count} test, with {failure_count} failures ({unexpected_count} unexpected) in {test_duration:.3f} ({total_duration:.3f}) seconds"
    )

    test_suite_name = alias_field('TestSuiteName')
    end_time = alias_field('EndTime')
    run_count = alias_field('RunCount')
    failure_count = alias_field('FailureCount')
    unexpected_count = alias_field('UnexpectedCount')
    test_duration = alias_field('TestDuration')
    total_duration = alias_field('TotalDuration')

    def __repr__(self):
        """
        Returns:
            str
        """
        return self.MESSAGE.format(
            test_suite_name=self.test_suite_name, end_time=self.end_time,
            run_count=self.run_count, failure_count=self.failure_count,
            unexpected_count=self.unexpected_count,
            test_duration=self.test_duration,
            total_duration=self.total_duration,
        )


class XCUITestRunner(object):
    def __init__(self, lockdown=None):
        self._lockdown = lockdown if lockdown else LockdownClient()
        self._installation = InstallationProxy(self._lockdown)

    def get_value(self, key = '', domain = "", no_session = False):
        """ key can be: ProductVersion
        Args:
            key (str):
            domain (str): com.apple.disk_usage
            no_session: set to True when not paired
        """
        return self._lockdown.getValue(domain, key)

    def _connect_testmanagerd_lockdown(self):
        """ connect to testmanagerd lockdown service
        Returns:
            DTXService: connected service
        """
        if self.major_version() >= 14:
            conn = self._lockdown.startService("com.apple.testmanagerd.lockdown.secure")
        else:
            conn = self._lockdown.startService("com.apple.testmanagerd.lockdown")
        return DTXService(conn)

    def _fnmatch_find_bundle_id(self, bundle_id):
        """
        Args:
            bundle_id (str): application bundle id
        Returns:
            str: found bundle id
        """
        bundle_ids = []
        for binfo in self._installation.iter_installed(attrs=['CFBundleIdentifier']):
            if fnmatch.fnmatch(binfo['CFBundleIdentifier'], bundle_id):
                bundle_ids.append(binfo['CFBundleIdentifier'])
        if not bundle_ids:
            raise MuxError("No app matches", bundle_id)

        # use irma first
        bundle_ids.sort(
            key=lambda v: v != 'com.facebook.wda.irmarunner.xctrunner')
        return bundle_ids[0]

    def _launch_wda_app(self,
            bundle_id,
            session_identifier,
            xctest_configuration,
            quit_event = None,
            test_runner_env = None,
            test_runner_args = None
        ):  # pid
        """
        Args:
            bundle_id (str): application bundle id
            session_identifier (uuid.UUID): session idendifier
            xctest_configuration (bplist.XCTestConfiguration): configuration
            quit_event (threading.Event): app quit event
            test_runner_env (Optional[dict]): test runner for env
            test_runner_args (Optional[list]): test runner args
        Returns:
            ServiceInstruments: connected service
            int: pid
        """
        app_info = self._installation.find_bundle_id(bundle_id)
        sign_identity = app_info.get("SignerIdentity", "")
        logger.info("SignIdentity: %r", sign_identity)

        app_container = app_info['Container']

        # CFBundleName always endswith -Runner
        exec_name = app_info['CFBundleExecutable']
        logger.info("CFBundleExecutable: %s", exec_name)
        assert exec_name.endswith("-Runner"), "Invalid CFBundleExecutable: %s" % exec_name
        target_name = exec_name[:-len("-Runner")]

        xctest_path = "/tmp/{}-{}.xctestconfiguration".format(
            target_name, str(session_identifier).upper())  # yapf: disable
        xctest_content = bplist.objc_encode(xctest_configuration)

        # fsync = self.app_sync(bundle_id, command="VendContainer")
        # for fname in fsync.listdir("/tmp"):
        #     if fname.endswith(".xctestconfiguration"):
        #         logger.debug("remove /tmp/%s", fname)
        #         fsync.remove("/tmp/" + fname)
        # fsync.push_content(xctest_path, xctest_content)

        fsync = HouseArrestService(self._lockdown)
        fsync.send_command(bundle_id)
        for fname in fsync.read_directory("/tmp"):
            if fname.endswith(".xctestconfiguration"):
                logging.debug("remove /tmp/%s", fname)
                fsync.file_remove("/tmp/" + fname)
        fsync.set_file_contents(xctest_path, xctest_content)

        # service: com.apple.instruments.remoteserver
        conn = ServiceInstruments(self._lockdown)
        channel = conn.make_channel("com.apple.instruments.server.services.processcontrol")

        conn.call_message(channel, "processIdentifierForBundleIdentifier:", [bundle_id])
        # launch app
        identifier = "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:"
        app_path = app_info['Path']

        xctestconfiguration_path = app_container + xctest_path  # xctest_path="/tmp/WebDriverAgentRunner-" + str(session_identifier).upper() + ".xctestconfiguration"
        logger.debug("AppPath: %s", app_path)
        logger.debug("AppContainer: %s", app_container)
        app_env = {
            'CA_ASSERT_MAIN_THREAD_TRANSACTIONS': '0',
            'CA_DEBUG_TRANSACTIONS': '0',
            'DYLD_FRAMEWORK_PATH': app_path + '/Frameworks:',
            'DYLD_LIBRARY_PATH': app_path + '/Frameworks',
            'MTC_CRASH_ON_REPORT': '1',
            'NSUnbufferedIO': 'YES',
            'SQLITE_ENABLE_THREAD_ASSERTIONS': '1',
            'WDA_PRODUCT_BUNDLE_IDENTIFIER': '',
            'XCTestBundlePath': "{}/PlugIns/{}.xctest".format(app_info['Path'], target_name),
            'XCTestConfigurationFilePath': xctestconfiguration_path,
            'XCODE_DBG_XPC_EXCLUSIONS': 'com.apple.dt.xctestSymbolicator',
            'MJPEG_SERVER_PORT': '',
            'USE_PORT': '',
            # maybe no needed
            'LLVM_PROFILE_FILE': app_container + "/tmp/%p.profraw", # %p means pid
        } # yapf: disable
        if test_runner_env:
            app_env.update(test_runner_env)

        if self.major_version() >= 11:
            app_env['DYLD_INSERT_LIBRARIES'] = '/Developer/usr/lib/libMainThreadChecker.dylib'
            app_env['OS_ACTIVITY_DT_MODE'] = 'YES'

        app_args = [
            '-NSTreatUnknownArgumentsAsOpen', 'NO',
            '-ApplePersistenceIgnoreState', 'YES'
        ]
        app_args.extend(test_runner_args or [])
        app_options = {'StartSuspendedKey': False}
        if self.major_version() >= 12:
            app_options['ActivateSuspended'] = True

        pid = conn.call_message(
            channel, identifier,
            [app_path, bundle_id, app_env, app_args, app_options])
        if not isinstance(pid, int):
            logger.error("Launch failed: %s", pid)
            raise MuxError("Launch failed")

        logger.info("Launch %r pid: %d", bundle_id, pid)
        aux = AUXMessageBuffer()
        aux.append_obj(pid)
        conn.call_message(channel, "startObservingPid:", aux)

        def _callback(m):
            """
            Args:
                m (DTXMessage): callback message
            """
            # logger.info("output: %s", m.result)
            if m is None:
                logger.warning("WebDriverAgentRunner quitted")
                return
            if m.flags == 0x02:
                method, args = m.result
                if method == 'outputReceived:fromProcess:atTime:':
                    # logger.info("Output: %s", args[0].strip())
                    logger.debug("logProcess: %s", args[0].rstrip())
                    # XCTestOutputBarrier is just ouput separators, no need to
                    # print them in the logs.
                    if args[0].rstrip() != 'XCTestOutputBarrier':
                        logger.debug('%s', args[0].rstrip())
                    # In low iOS versions, 'Using singleton test manager' may not be printed... mark wda launch status = True if server url has been printed
                    if "ServerURLHere" in args[0]:
                        logger.info("%s", args[0].rstrip())
                        logger.info("WebDriverAgent start successfully")

        def _log_message_callback(m):
            """
            Args:
                m (DTXMessage): callback message
            """
            identifier, args = m.result
            logger.debug("logConsole: %s", args)
            if isinstance(args, (tuple, list)):
                for msg in args:
                    msg = msg.rstrip() if isinstance(msg, str) else msg
                    logger.debug('%s', msg)
            else:
                logger.debug('%s', args)

        conn.register_callback("_XCT_logDebugMessage:", _log_message_callback)
        conn.register_callback(Event.NOTIFICATION, _callback)
        if quit_event:
            conn.register_callback(Event.FINISHED, lambda _: quit_event.set())
        return conn, pid

    def major_version(self):
        """
        Returns:
            int: major version
        """
        version = self.get_value("ProductVersion")
        return int(version.split(".")[0])

    def _gen_xctest_configuration(
        self,
        app_info,
        session_identifier,
        target_app_bundle_id,
        target_app_env,
        target_app_args,
        tests_to_run = None
    ):
        """
        generate xctest configuration

        Args:
            app_info (dict): application information
            session_identifier (uuid.UUID): session identifier
            target_app_bundle_id (str): application bundle id
            target_app_env (Optional[dict]): app environment
            target_app_args (Optional[list]): app arguments
            tests_to_run (Optional[set]): tests to run

        Returns:
            bplist.XCTestConfiguration: xctest configuration
        """
        # CFBundleName always endswith -Runner
        exec_name = app_info['CFBundleExecutable']
        assert exec_name.endswith("-Runner"), "Invalid CFBundleExecutable: %s" % exec_name
        target_name = exec_name[:-len("-Runner")]

        # xctest_path = f"/tmp/{target_name}-{str(session_identifier).upper()}.xctestconfiguration"  # yapf: disable
        return bplist.XCTestConfiguration({
            "testBundleURL": bplist.NSURL(None, "file://{}/PlugIns/{}.xctest".format(app_info['Path'], target_name)),
            "sessionIdentifier": session_identifier,
            "targetApplicationBundleID": target_app_bundle_id,
            "targetApplicationArguments": target_app_args or [],
            "targetApplicationEnvironment": target_app_env or {},
            "testsToRun": tests_to_run or set(),  # We can use "set()" or "None" as default value, but "{}" won't work because the decoding process regards "{}" as a dictionary.
            "testsMustRunOnMainThread": True,
            "reportResultsToIDE": True,
            "reportActivities": True,
            "automationFrameworkPath": "/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework",
        })  # yapf: disable

    def xcuitest(self, bundle_id, target_bundle_id=None,
                    test_runner_env={},
                    test_runner_args=None,
                    target_app_env=None,
                    target_app_args=None,
                    tests_to_run=None):
        """
        Launch xctrunner and wait until quit

        Args:
            bundle_id (str): xctrunner bundle id
            target_bundle_id (str): optional, launch WDA-UITests will not need it
            test_runner_env (dict[str, str]): optional, the environment variables to be passed to the test runner
            test_runner_args (list[str]): optional, the command line arguments to be passed to the test runner
            target_app_env (dict[str, str]): optional, the environmen variables to be passed to the target app
            target_app_args (list[str]): optional, the command line arguments to be passed to the target app
            tests_to_run (set[str]): optional, the specific test classes or test methods to run
        """
        product_version = self.get_value("ProductVersion")
        logger.info("ProductVersion: %s", product_version)
        logger.info("UDID: %s", self._lockdown.udid)

        XCODE_VERSION = 29
        session_identifier = uuid.uuid4()

        # when connections closes, this event will be set
        quit_event = threading.Event()

        ##
        ## IDE 1st connection
        x1 = self._connect_testmanagerd_lockdown()

        # index: 427
        x1_daemon_chan = x1.make_channel(
            'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface'
        )

        if self.major_version() >= 11:
            identifier = '_IDE_initiateControlSessionWithProtocolVersion:'
            aux = AUXMessageBuffer()
            aux.append_obj(XCODE_VERSION)
            x1.call_message(x1_daemon_chan, identifier, aux)
        x1.register_callback(Event.FINISHED, lambda _: quit_event.set())

        ##
        ## IDE 2nd connection
        x2 = self._connect_testmanagerd_lockdown()
        x2_deamon_chan = x2.make_channel(
            'dtxproxy:XCTestManager_IDEInterface:XCTestManager_DaemonConnectionInterface'
        )
        x2.register_callback(Event.FINISHED, lambda _: quit_event.set())
        #x2.register_callback("pidDiedCallback:" # maybe no needed

        _start_flag = threading.Event()

        def _start_executing(m=None):
            """
            start executing tests

            Args:
                m (Optional[DTXMessage]): message
            """
            if _start_flag.is_set():
                return
            _start_flag.set()

            logger.info("Start execute test plan with IDE version: %d", XCODE_VERSION)
            x2.call_message(0xFFFFFFFF, '_IDE_startExecutingTestPlanWithProtocolVersion:', [XCODE_VERSION], expects_reply=False)

        def _show_log_message(m):
            """
            Args:
                m (DTXMessage): message
            """
            logger.debug("logMessage: %s", m.result[1])
            if 'Received test runner ready reply' in ''.join(
                    m.result[1]):
                logger.info("Test runner ready detected")
                _start_executing()

            if isinstance(m.result[1], (tuple, list)):
                for msg in m.result[1]:
                    msg = msg.rstrip() if isinstance(msg, str) else msg
                    logger.debug('%s', msg)
            else:
                logger.debug('%s', m.result[1])

        test_results = []
        test_results_lock = threading.Lock()

        def _record_test_result_callback(m):
            """
            Args:
                m (DTXMessage): message
            """
            result = None
            if isinstance(m.result, (tuple, list)) and len(m.result) >= 1:
                if isinstance(m.result[1], (tuple, list)):
                    try:
                        result = XCTestResult(*m.result[1])
                    except TypeError:
                        pass
            if not result:
                logger.warning('Ignore unknown test result message: %s', m)
                return
            with test_results_lock:
                test_results.append(result)

        x2.register_callback(
            '_XCT_testBundleReadyWithProtocolVersion:minimumVersion:',
            _start_executing)  # This only happends <= iOS 13
        x2.register_callback('_XCT_logDebugMessage:', _show_log_message)
        x2.register_callback(
            "_XCT_testSuite:didFinishAt:runCount:withFailures:unexpected:testDuration:totalDuration:",
            _record_test_result_callback)

        app_info = self._installation.find_bundle_id(bundle_id)
        xctest_configuration = self._gen_xctest_configuration(app_info, session_identifier, target_bundle_id, target_app_env, target_app_args, tests_to_run)

        def _ready_with_caps_callback(m):
            """
            Args:
                m (DTXMessage): message
            """
            x2.send_dtx_message(m.channel_id,
                                payload=DTXPayload.build_other(0x03, xctest_configuration),
                                message_id=m.message_id)

        x2.register_callback('_XCT_testRunnerReadyWithCapabilities:', _ready_with_caps_callback)

        # index: 469
        identifier = '_IDE_initiateSessionWithIdentifier:forClient:atPath:protocolVersion:'
        aux = AUXMessageBuffer()
        aux.append_obj(session_identifier)
        aux.append_obj(str(session_identifier) + '-6722-000247F15966B083')
        aux.append_obj('/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild')
        aux.append_obj(XCODE_VERSION)
        result = x2.call_message(x2_deamon_chan, identifier, aux)
        if "NSError" in str(result):
            raise RuntimeError("Xcode Invocation Failed: {}".format(result))

        # launch test app
        # index: 1540
        # xclogger = setup_logger(name='xcuitest')
        _, pid = self._launch_wda_app(
            bundle_id,
            session_identifier,
            xctest_configuration=xctest_configuration,
            test_runner_env=test_runner_env,
            test_runner_args=test_runner_args)

        # xcode call the following commented method, twice
        # but it seems can be ignored

        # identifier = '_IDE_collectNewCrashReportsInDirectories:matchingProcessNames:'
        # aux = AUXMessageBuffer()
        # aux.append_obj(['/var/mobile/Library/Logs/CrashReporter/'])
        # aux.append_obj(['SpringBoard', 'backboardd', 'xctest'])
        # result = x1.call_message(chan, identifier, aux)
        # logger.debug("result: %s", result)

        # identifier = '_IDE_collectNewCrashReportsInDirectories:matchingProcessNames:'
        # aux = AUXMessageBuffer()
        # aux.append_obj(['/var/mobile/Library/Logs/CrashReporter/'])
        # aux.append_obj(['SpringBoard', 'backboardd', 'xctest'])
        # result = x1.call_message(chan, identifier, aux)
        # logger.debug("result: %s", result)

        # after app launched, operation bellow must be send in 0.1s
        # or wda will launch failed
        if self.major_version() >= 12:
            identifier = '_IDE_authorizeTestSessionWithProcessID:'
            aux = AUXMessageBuffer()
            aux.append_obj(pid)
            result = x1.call_message(x1_daemon_chan, identifier, aux)
        elif self.major_version() <= 9:
            identifier = '_IDE_initiateControlSessionForTestProcessID:'
            aux = AUXMessageBuffer()
            aux.append_obj(pid)
            result = x1.call_message(x1_daemon_chan, identifier, aux)
        else:
            identifier = '_IDE_initiateControlSessionForTestProcessID:protocolVersion:'
            aux = AUXMessageBuffer()
            aux.append_obj(pid)
            aux.append_obj(XCODE_VERSION)
            result = x1.call_message(x1_daemon_chan, identifier, aux)

        if "NSError" in str(result):
            raise RuntimeError("Xcode Invocation Failed: {}".format(result))

        # wait for quit
        # on windows threading.Event.wait can't handle ctrl-c
        while not quit_event.wait(.1):
            pass

        test_result_str = "\n".join(map(str, test_results))
        if any(result.failure_count > 0 for result in test_results):
                raise RuntimeError(
                    "Xcode test failed on device with test results:\n"
                    "{}".format(test_result_str)
                )

        logger.info("xctrunner quited with result:\n%s", test_result_str)

    def runwda(self, fuzzy_bundle_id="com.*.xctrunner", target_bundle_id=None,
               test_runner_env=None,
               test_runner_args=None,
               target_app_env=None,
               target_app_args=None,
               tests_to_run=None):
        """ Alias of xcuitest
        Args:
            target_bundle_id (str): optional, launch WDA-UITests will not need it
            test_runner_env (dict[str, str]): optional, the environment variables to be passed to the test runner
            test_runner_args (list[str]): optional, the command line arguments to be passed to the test runner
            target_app_env (dict[str, str]): optional, the environmen variables to be passed to the target app
            target_app_args (list[str]): optional, the command line arguments to be passed to the target app
            tests_to_run (set[str]): optional, the specific test classes or test methods to run
        """
        bundle_id = self._fnmatch_find_bundle_id(fuzzy_bundle_id)
        logger.info("BundleID: %s", bundle_id)
        return self.xcuitest(bundle_id, target_bundle_id=target_bundle_id,
                             test_runner_env=test_runner_env,
                             test_runner_args=test_runner_args,
                             target_app_env=target_app_env,
                             target_app_args=target_app_args,
                             tests_to_run=tests_to_run)


if __name__ == '__main__':
    bundle_id = 'com.tencent.testsolar.xctagent.xctrunner'
    runner = XCUITestRunner()
    runner.runwda(fuzzy_bundle_id=bundle_id)
