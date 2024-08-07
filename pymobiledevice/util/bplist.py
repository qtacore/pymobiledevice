# -*- coding: utf-8 -*-

"""
http://github.com/farcaller/bplist-python/blob/master/bplist.py
"""
from __future__ import print_function
import struct
import plistlib
import datetime
import copy
import uuid
import pprint
from .plistlib2 import (loads, dumps, FMT_BINARY, UID) # yapf: disable


class BPListWriter(object):
    def __init__(self, objects):
        self.bplist = ""
        self.objects = objects

    def binary(self):
        '''binary -> string

        Generates bplist
        '''
        self.data = 'bplist00'

        # TODO: flatten objects and count max length size

        # TODO: write objects and save offsets

        # TODO: write offsets

        # TODO: write metadata

        return self.data

    def write(self, filename):
        '''

        Writes bplist to file
        '''
        if self.bplist != "":
            pass
            # TODO: save self.bplist to file
        else:
            raise Exception('BPlist not yet generated')

class BPlistReader(object):
    def __init__(self, s):
        self.data = s
        self.objects = []
        self.resolved = {}

    def __unpackIntStruct(self, sz, s):
        '''__unpackIntStruct(size, string) -> int

        Unpacks the integer of given size (1, 2 or 4 bytes) from string
        '''
        if   sz == 1:
            ot = '!B'
        elif sz == 2:
            ot = '!H'
        elif sz == 4:
            ot = '!I'
        elif sz == 8:
            ot = '!Q'
        else:
            raise Exception('int unpack size '+str(sz)+' unsupported')
        return struct.unpack(ot, s)[0]

    def __unpackInt(self, offset):
        '''__unpackInt(offset) -> int

        Unpacks int field from plist at given offset
        '''
        return self.__unpackIntMeta(offset)[1]

    def __unpackIntMeta(self, offset):
        '''__unpackIntMeta(offset) -> (size, int)

        Unpacks int field from plist at given offset and returns its size and value
        '''
        obj_header = struct.unpack('!B', self.data[offset])[0]
        obj_type, obj_info = (obj_header & 0xF0), (obj_header & 0x0F)
        int_sz = 2**obj_info
        return int_sz, self.__unpackIntStruct(int_sz, self.data[offset+1:offset+1+int_sz])

    def __resolveIntSize(self, obj_info, offset):
        '''__resolveIntSize(obj_info, offset) -> (count, offset)

        Calculates count of objref* array entries and returns count and offset to first element
        '''
        if obj_info == 0x0F:
            ofs, obj_count = self.__unpackIntMeta(offset+1)
            objref = offset+2+ofs
        else:
            obj_count = obj_info
            objref = offset+1
        return obj_count, objref

    def __unpackFloatStruct(self, sz, s):
        '''__unpackFloatStruct(size, string) -> float

        Unpacks the float of given size (4 or 8 bytes) from string
        '''
        if   sz == 4:
            ot = '!f'
        elif sz == 8:
            ot = '!d'
        else:
            raise Exception('float unpack size '+str(sz)+' unsupported')
        return struct.unpack(ot, s)[0]

    def __unpackFloat(self, offset):
        '''__unpackFloat(offset) -> float

        Unpacks float field from plist at given offset
        '''
        obj_header = struct.unpack('!B', self.data[offset])[0]
        obj_type, obj_info = (obj_header & 0xF0), (obj_header & 0x0F)
        int_sz = 2**obj_info
        return int_sz, self.__unpackFloatStruct(int_sz, self.data[offset+1:offset+1+int_sz])

    def __unpackDate(self, offset):
        td = int(struct.unpack(">d", self.data[offset+1:offset+9])[0])
        return datetime.datetime(year=2001,month=1,day=1) + datetime.timedelta(seconds=td)

    def __unpackItem(self, offset):
        '''__unpackItem(offset)

        Unpacks and returns an item from plist
        '''
        obj_header = struct.unpack('!B', self.data[offset])[0]
        obj_type, obj_info = (obj_header & 0xF0), (obj_header & 0x0F)
        if   obj_type == 0x00:
            if   obj_info == 0x00: # null   0000 0000
                return None
            elif obj_info == 0x08: # bool   0000 1000           // false
                return False
            elif obj_info == 0x09: # bool   0000 1001           // true
                return True
            elif obj_info == 0x0F: # fill   0000 1111           // fill byte
                raise Exception("0x0F Not Implemented") # this is really pad byte, FIXME
            else:
                raise Exception('unpack item type '+str(obj_header)+' at '+str(offset)+ 'failed')
        elif obj_type == 0x10: #     int    0001 nnnn   ...     // # of bytes is 2^nnnn, big-endian bytes
            return self.__unpackInt(offset)
        elif obj_type == 0x20: #    real    0010 nnnn   ...     // # of bytes is 2^nnnn, big-endian bytes
            return self.__unpackFloat(offset)
        elif obj_type == 0x30: #    date    0011 0011   ...     // 8 byte float follows, big-endian bytes
            return self.__unpackDate(offset)
        elif obj_type == 0x40: #    data    0100 nnnn   [int]   ... // nnnn is number of bytes unless 1111 then int count follows, followed by bytes
            obj_count, objref = self.__resolveIntSize(obj_info, offset)
            return plistlib.Data(self.data[objref:objref+obj_count]) # XXX: we return data as str
        elif obj_type == 0x50: #    string  0101 nnnn   [int]   ... // ASCII string, nnnn is # of chars, else 1111 then int count, then bytes
            obj_count, objref = self.__resolveIntSize(obj_info, offset)
            return self.data[objref:objref+obj_count]
        elif obj_type == 0x60: #    string  0110 nnnn   [int]   ... // Unicode string, nnnn is # of chars, else 1111 then int count, then big-endian 2-byte uint16_t
            obj_count, objref = self.__resolveIntSize(obj_info, offset)
            return self.data[objref:objref+obj_count*2].decode('utf-16be')
        elif obj_type == 0x80: #    uid     1000 nnnn   ...     // nnnn+1 is # of bytes
            # FIXME: Accept as a string for now
            obj_count, objref = self.__resolveIntSize(obj_info, offset)
            return plistlib.Data(self.data[objref:objref+obj_count])
        elif obj_type == 0xA0: #    array   1010 nnnn   [int]   objref* // nnnn is count, unless '1111', then int count follows
            obj_count, objref = self.__resolveIntSize(obj_info, offset)
            arr = []
            for i in range(obj_count):
                arr.append(self.__unpackIntStruct(self.object_ref_size, self.data[objref+i*self.object_ref_size:objref+i*self.object_ref_size+self.object_ref_size]))
            return arr
        elif obj_type == 0xC0: #   set      1100 nnnn   [int]   objref* // nnnn is count, unless '1111', then int count follows
            # XXX: not serializable via apple implementation
            raise Exception("0xC0 Not Implemented") # FIXME: implement
        elif obj_type == 0xD0: #   dict     1101 nnnn   [int]   keyref* objref* // nnnn is count, unless '1111', then int count follows
            obj_count, objref = self.__resolveIntSize(obj_info, offset)
            keys = []
            for i in range(obj_count):
                keys.append(self.__unpackIntStruct(self.object_ref_size, self.data[objref+i*self.object_ref_size:objref+i*self.object_ref_size+self.object_ref_size]))
            values = []
            objref += obj_count*self.object_ref_size
            for i in range(obj_count):
                values.append(self.__unpackIntStruct(self.object_ref_size, self.data[objref+i*self.object_ref_size:objref+i*self.object_ref_size+self.object_ref_size]))
            dic = {}
            for i in range(obj_count):
                dic[keys[i]] = values[i]
            return dic
        else:
            raise Exception('don\'t know how to unpack obj type '+hex(obj_type)+' at '+str(offset))

    def __resolveObject(self, idx):
        try:
            return self.resolved[idx]
        except KeyError:
            obj = self.objects[idx]
            if type(obj) == list:
                newArr = []
                for i in obj:
                    newArr.append(self.__resolveObject(i))
                self.resolved[idx] = newArr
                return newArr
            if type(obj) == dict:
                newDic = {}
                for k,v in obj.iteritems():
                    rk = self.__resolveObject(k)
                    rv = self.__resolveObject(v)
                    newDic[rk] = rv
                self.resolved[idx] = newDic
                return newDic
            else:
                self.resolved[idx] = obj
                return obj

    def parse(self):
        # read header
        if self.data[:8] != 'bplist00':
            raise Exception('Bad magic')

        # read trailer
        self.offset_size, self.object_ref_size, self.number_of_objects, self.top_object, self.table_offset = struct.unpack('!6xBB4xI4xI4xI', self.data[-32:])
        #print "** plist offset_size:",self.offset_size,"objref_size:",self.object_ref_size,"num_objs:",self.number_of_objects,"top:",self.top_object,"table_ofs:",self.table_offset

        # read offset table
        self.offset_table = self.data[self.table_offset:-32]
        self.offsets = []
        ot = self.offset_table
        for i in xrange(self.number_of_objects):
            offset_entry = ot[:self.offset_size]
            ot = ot[self.offset_size:]
            self.offsets.append(self.__unpackIntStruct(self.offset_size, offset_entry))
        #print "** plist offsets:",self.offsets

        # read object table
        self.objects = []
        k = 0
        for i in self.offsets:
            obj = self.__unpackItem(i)
            #print "** plist unpacked",k,type(obj),obj,"at",i
            k += 1
            self.objects.append(obj)

        # rebuild object tree
        #for i in range(len(self.objects)):
        #    self.__resolveObject(i)

        # return root object
        return self.__resolveObject(self.top_object)

    @classmethod
    def plistWithString(cls, s):
        parser = cls(s)
        return parser.parse()

    @classmethod
    def plistWithFile(cls, f):
        file = open(f,"rb")
        parser = cls(file.read())
        file.close()
        return parser.parse()


class InvalidFileException (ValueError):
    def __init__(self, message="Invalid file"):
        ValueError.__init__(self, message)


class DecodeNotSupportedError(Exception):
    pass


class InvalidNSKeyedArchiverFormat(Exception):
    """ Not a valid format NSKeyedArchiver """
    pass


class DTSysmonTapMessage:
    """ Usally point to a NSDictionary """
    pass


class NSIgnore:
    """ Just don't parse it """
    pass


class NSBaseObject(object):
    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value (Any):
        """
        raise NotImplementedError()


class NSError(Exception):
    def __init__(self, code, domain, user_info):
        self.code = code  # eg: 1
        self.domain = domain  # eg: DTXMessage
        self.user_info = user_info  # eg: {'NSLocalizedDescription': 'Unable to invoke -[<D'}

    def __str__(self):
        return "NSError(CODE:{} DOMAIN:{} INFO:{})".format(
            self.code, self.domain,
            pprint.pformat(self.user_info))  #['NSLocalizedDescription'])

    def __repr__(self):
        return str(self)

    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        """
        code = ns_info['NSCode']
        domain = _parse_object(objects, ns_info['NSDomain'])
        user_info = _parse_object(objects, ns_info['NSUserInfo'])
        return NSError(code, domain, user_info)


class NSNull(NSBaseObject):
    """
    NSNull() always return the same instance
    """

    _instance = None

    def __new__(cls):
        if not NSNull._instance:
            NSNull._instance = super(NSNull, cls).__new__(cls)
        return NSNull._instance

    def __bool__(self):
        return False

    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value (Union[int, str]):
        """
        ns_info = {}
        objects.append(ns_info)
        ns_info['$class'] = UID(len(objects))
        objects.append({
            "$classname": "NSNull",
            "$classes": ["NSNull", "NSObject"],
        })


class NSObject(NSBaseObject):
    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value (Union[int, str]):
        """
        if not isinstance(value, (int, str)):
            raise ValueError("NSObject not supported encode value", value,
                             type(value))
        objects.append(value)


class NSSet(NSBaseObject, set):
    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value (set):
        """
        ns_objs = []
        ns_info = {
            "NS.objects": ns_objs,
        }
        objects.append(ns_info)
        for v in value:
            uid = _encode_any(objects, v)
            ns_objs.append(uid)

        ns_info['$class'] = UID(len(objects))
        objects.append({
            "$classname": "NSSet",
            "$classes": ["NSSet", "NSObject"],
        })


class NSArray(NSBaseObject, list):
    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value (List[Any]):
        """
        ns_objs = []
        ns_info = {
            "NS.objects": ns_objs,
        }
        objects.append(ns_info)

        for v in value:
            uid = _encode_any(objects, v)
            ns_objs.append(uid)

        ns_info["$class"] = UID(len(objects))
        objects.append({
            "$classname": "NSArray",
            "$classes": ["NSArray", "NSObject"],
        })


class NSDictionary(NSBaseObject, dict):
    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value (dict):
        """
        ns_keys = []
        ns_objs = []

        ns_info = {
            "NS.keys": ns_keys,
            "NS.objects": ns_objs,
        }
        objects.append(ns_info)

        for k, v in value.items():
            ns_keys.append(UID(len(objects)))
            objects.append(k)

            uid = _encode_any(objects, v)
            ns_objs.append(uid)

        ns_info["$class"] = UID(len(objects))
        objects.append({
            "$classname": "NSDictionary",
            "$classes": ["NSDictionary", "NSObject"],
        })


class XCTestConfiguration(NSBaseObject):
    _default = {
        # 'testBundleURL': UID(3), # NSURL(None, file:///private/var/containers/Bundle/.../WebDriverAgentRunner-Runner.app/PlugIns/WebDriverAgentRunner.xctest)
        # 'sessionIdentifier': UID(8), # UUID
        'aggregateStatisticsBeforeCrash': {
            'XCSuiteRecordsKey': {}
        },
        'automationFrameworkPath': '/Developer/Library/PrivateFrameworks/XCTAutomationSupport.framework',
        'baselineFileRelativePath': None,
        'baselineFileURL': None,
        'defaultTestExecutionTimeAllowance': None,
        'disablePerformanceMetrics': False,
        'emitOSLogs': False,
        'formatVersion': 2,  # store in UID
        'gatherLocalizableStringsData': False,
        'initializeForUITesting': True,
        'maximumTestExecutionTimeAllowance': None,
        'productModuleName': "WebDriverAgentRunner",  # set to other value is also OK
        'randomExecutionOrderingSeed': None,
        'reportActivities': True,
        'reportResultsToIDE': True,
        'systemAttachmentLifetime': 2,
        'targetApplicationArguments': [],  # maybe useless
        'targetApplicationBundleID': None,
        'targetApplicationEnvironment': None,
        'targetApplicationPath': "/whatever-it-does-not-matter/but-should-not-be-empty",
        'testApplicationDependencies': {},
        'testApplicationUserOverrides': None,
        'testBundleRelativePath': None,
        'testExecutionOrdering': 0,
        'testTimeoutsEnabled': False,
        'testsDrivenByIDE': False,
        'testsMustRunOnMainThread': True,
        'testsToRun': None,
        'testsToSkip': None,
        'treatMissingBaselinesAsFailures': False,
        'userAttachmentLifetime': 1
    }

    def __init__(self, kv):
        """
        Args:
            kn (dict):
        """
        # self._kv = kv
        assert 'testBundleURL' in kv and isinstance(kv['testBundleURL'], NSURL)
        assert 'sessionIdentifier' in kv and isinstance(
            kv['sessionIdentifier'], uuid.UUID)

        self._kv = copy.deepcopy(self._default)
        self._kv.update(kv)

    def __str__(self):
        return "XCTestConfiguration(" + pprint.pformat(self._kv) + ")"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other):
        return self._kv == other._kv

    def __setitem__(self, key, val):
        """
        Args:
            key (str):
            value (Any):
        """
        assert isinstance(key, str)
        self._kv[key] = val

    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value:
        """
        ns_info = {}
        objects.append(ns_info)
        ns_info['$class'] = UID(len(objects))
        objects.append({
            '$classes': ["XCTestConfiguration", 'NSObject'],
            '$classname': "XCTestConfiguration"
        })
        for (k, v) in value._kv.items():
            if k not in ['formatVersion'] and isinstance(v, (bool, int)):
                ns_info[k] = v
            else:
                ns_info[k] = _encode_any(objects, v)

    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        """
        info = ns_info.copy()
        info.pop("$class")
        for key in info.keys():
            idx = info[key]
            if isinstance(idx, UID):
                info[key] = _parse_object(objects, idx.data)
        return XCTestConfiguration(info)


class DTActivityTraceTapMessage(NSBaseObject):
    def __init__(self, tap_message):
        """
        Args:
            tap_message (list):
        """
        self._tap_message = tap_message

    def __str__(self):
        return "DTActivityTraceTapMessage - " + pprint.pformat(
            self._tap_message)

    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        """
        tap_message = _parse_object(objects, ns_info['DTTapMessagePlist'])
        return DTActivityTraceTapMessage(tap_message)


class NSString(NSBaseObject, str):
    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        Returns:
            str:
        """
        return NSString(ns_info['NS.string'])


class NSUUID(NSBaseObject, uuid.UUID):
    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            ns_info (uuid.UUID):
        """
        ns_info = {
            "NS.uuidbytes": value.bytes,
        }
        objects.append(ns_info)
        ns_info['$class'] = UID(len(objects))
        objects.append({
            '$classes': ['NSUUID', 'NSObject'],
            '$classname': 'NSUUID'
        })

    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        Returns:
            uuid.UUID
        """
        return uuid.UUID(bytes=ns_info['NS.uuidbytes'])


class NSURL(NSBaseObject):
    def __init__(self, base, relative):
        self._base = base
        self._relative = relative

    def __eq__(self, other):
        """
        Returns:
            bool:
        """
        return self._base == other._base and self._relative == other._relative

    def __str__(self):
        return "NSURL({}, {})".format(self._base, self._relative)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def encode(objects, value):
        """
        Args:
            objects (list):
            value:
        """
        ns_info = {}
        objects.append(ns_info)

        ns_info['NS.base'] = _encode_any(objects, value._base)
        ns_info['NS.relative'] = _encode_any(objects, value._relative)

        ns_info['$class'] = UID(len(objects))
        objects.append({
            '$classes': ['NSURL', 'NSObject'],
            '$classname': 'NSURL'
        })

    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        """
        base = _parse_object(objects, ns_info['NS.base'])
        relative = _parse_object(objects, ns_info['NS.relative'])
        return NSURL(base, relative)


# DTActivityTraceTapMessage
# NotImplementedError: 'DTActivityTraceTapMessage' decode not supported
#   ns_info: {'$class': UID(6), 'DTTapMessagePlist': UID(2)}
#   ns_objects: [   '$null',
#     {'$class': UID(6), 'DTTapMessagePlist': UID(2)},
#     {'$class': UID(5), 'NS.keys': [UID(3)], 'NS.objects': [UID(4)]},
#     'k',
#     0,
#     {   '$classes': ['NSMutableDictionary', 'NSDictionary', 'NSObject'],
#         '$classname': 'NSMutableDictionary'},
#     {   '$classes': ['DTActivityTraceTapMessage', 'DTTapMessage', 'NSObject'],
#         '$classname': 'DTActivityTraceTapMessage'}]


class XCActivityRecord(NSBaseObject, dict):
    _keys = ('activityType', 'attachments', 'finish', 'start', 'title', 'uuid')

    def __repr__(self):
        attrs = []
        for key in self._keys:
            attrs.append('{}={}'.format(key, self[key]))

        return 'XCActivityRecord({})'.format(', '.join(attrs))

    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        """
        ret = XCActivityRecord()
        for key in XCActivityRecord._keys:
            ret[key] = _parse_object(objects, ns_info[key])
        return ret


# NotImplementedError: 'NSException' decode not supported
#   ns_info: {'$class': UID(8),
#  'NS.name': UID(6),
#  'NS.reason': UID(7),
#  'NS.userinfo': UID(0)}
#   ns_objects: [   '$null',
#     {'$class': UID(10), 'NSCode': 1, 'NSDomain': UID(2), 'NSUserInfo': UID(3)},
#     'DTXMessage',
#     {'$class': UID(9), 'NS.keys': [UID(4)], 'NS.objects': [UID(5)]},
#     'DTXExceptionKey',
#     {   '$class': UID(8),
#         'NS.name': UID(6),
#         'NS.reason': UID(7),
#         'NS.userinfo': UID(0)},
#     'DTXMessageInvocationException',
#     'Unable to invoke -[<XCIDESession: 0x101527c20> (socket 4) created '
#     '2020年6月12日 星期五 中国标准时间 16:32:21 '
#     '_IDE_initiateControlSessionWithProtocolVersion:] - it does not respond to '
#     'the selector',
#     {'$classes': ['NSException', 'NSObject'], '$classname': 'NSException'},
#     {'$classes': ['NSDictionary', 'NSObject'], '$classname': 'NSDictionary'},
#     {'$classes': ['NSError', 'NSObject'], '$classname': 'NSError'}]
class NSException(NSBaseObject):
    def __init__(self, name, reason, userinfo):
        self._name = name
        self._reason = reason
        self._userinfo = userinfo

    def __str__(self):
        return "NSException(name={} reason={} userinfo={}".format(
            self._name, self._reason, self._userinfo)

    def __repr__(self):
        return str(self)

    @staticmethod
    def decode(objects, ns_info):
        """
        Args:
            objects (list):
            ns_info (dict):
        """
        name = _parse_object(objects, ns_info['NS.name'])
        reason = _parse_object(objects, ns_info['NS.reason'])
        userinfo = _parse_object(objects, ns_info['NS.userinfo'])
        return NSException(name, reason, userinfo)


# XCTTestIdentifier
    # ns_info: {'c': UID(2), 'o': 1, '$class': UID(5)}
    # objects: ['$null',
    #     {'c': UID(2), 'o': 1, '$class': UID(5)},
    #     {'NS.objects': [UID(3)], '$class': UID(4)},
    #     'All tests',
    #     {'$classname': 'NSArray', '$classes': ['NSArray', 'NSObject']},
    #     {'$classname': 'XCTTestIdentifier', '$classes': ['XCTTestIdentifier', 'NSObject']}
    # ]

# XCActivityRecord
# ns_info: {'$class': UID(10),
#  'activityType': UID(7),
#  'attachments': UID(8),
#  'finish': UID(0),
#  'start': UID(4),
#  'title': UID(6),
#  'uuid': UID(2)}
#   ns_objects: [   '$null',
#     {   '$class': UID(10),
#         'activityType': UID(7),
#         'attachments': UID(8),
#         'finish': UID(0),
#         'start': UID(4),
#         'title': UID(6),
#         'uuid': UID(2)},
#     {   '$class': UID(3),
#         'NS.uuidbytes': b"\xca0\xba\xb9\xf1^O\x18\xbd\xa8'X\xc2\xbbAG"},
#     {'$classes': ['NSUUID', 'NSObject'], '$classname': 'NSUUID'},
#     {'$class': UID(5), 'NS.time': 613636438.841612},
#     {'$classes': ['NSDate', 'NSObject'], '$classname': 'NSDate'},
#     'Start Test at 2020-06-12 14:33:58.841',
#     'com.apple.dt.xctest.activity-type.internal',
#     {'$class': UID(9), 'NS.objects': []},
#     {'$classes': ['NSArray', 'NSObject'], '$classname': 'NSArray'},
#     {   '$classes': ['XCActivityRecord', 'NSObject'],
#         '$classname': 'XCActivityRecord'}]

NoneType = type(None)

_ENCODE_MAP = {
    dict: NSDictionary,
    list: NSArray,
    set: NSSet,
    str: NSObject,
    int: NSObject,
    bool: NSObject,
    uuid.UUID: NSUUID,
    NoneType: NoneType,
    NSNull: NSNull,  # NSNull is a class, not null
    NSURL: NSURL,
    XCTestConfiguration: XCTestConfiguration,
}

_DECODE_MAP = {
    "NSDictionary": dict,
    "NSMutableDictionary": dict,
    "NSArray": list,
    "NSMutableArray": list,
    "NSSet": set,
    "NSMutableSet": set,
    "NSDate": datetime.datetime,
    "NSError": NSError,
    "NSUUID": uuid.UUID,
    "XCTestConfiguration": XCTestConfiguration,
    "NSNull": NSNull,
    "NSURL": NSURL,
    "DTActivityTraceTapMessage": DTActivityTraceTapMessage,
    "XCActivityRecord": XCActivityRecord,
    "NSException": NSException,
    "NSMutableString": NSString,
    # Ignored
    "DTSysmonTapMessage": NSIgnore,
    "DTTapHeartbeatMessage": NSIgnore,
    "DTTapStatusMessage": NSIgnore,
    "XCTAttachment": NSIgnore,
    "XCTCapabilities": NSIgnore,
    "XCTTestIdentifier": NSIgnore,
    "XCTestCaseRunConfiguration": NSIgnore,
}


def _encode_any(objects, value):
    """
    Args:
        objects (list):
        value (Any):
    Returns:
        UID
    """
    _type = type(value)
    _class = _ENCODE_MAP.get(_type)
    if not _class:
        raise ValueError("encode not support type: {}".format(_type))
    if _class == NoneType:
        return UID(0)

    uid = UID(len(objects))
    _class.encode(objects, value)
    return uid


def objc_encode(value):
    """
    Args:
        value (Any):
    Returns:
        bytes:
    """
    objects = ['$null']
    _encode_any(objects, value)
    pdata = {
        "$version": 100000,
        "$archiver": "NSKeyedArchiver",
        "$top": {
            "root": UID(1),
        },
        "$objects": objects
    }
    return dumps(pdata, fmt=FMT_BINARY)


def _parse_object(objects, index):
    """
    Args:
        objects (list):
        index (Union[int, UID]):
    Returns:
        Any:
    """
    if isinstance(index, UID):
        index = index.data

    if index == 0:
        return None

    obj = objects[index]
    if not isinstance(obj, dict):
        return obj

    ns_info = obj
    class_idx = ns_info['$class']
    class_name = objects[class_idx]["$classname"]
    _type = _DECODE_MAP.get(class_name)
    if not _type:
        raise DecodeNotSupportedError(
            class_name, "ns_info: {}\n  ns_objects: {}".format(
                pprint.pformat(ns_info), pprint.pformat(objects, indent=4)))

    if hasattr(_type, "decode") and callable(_type.decode):
        return _type.decode(objects, ns_info)
    elif _type == dict:
        value = {}
        ns_keys = ns_info['NS.keys']
        ns_objs = ns_info['NS.objects']
        for i in range(len(ns_keys)):
            key = objects[ns_keys[i].data]
            obj_idx = ns_objs[i].data
            value[key] = _parse_object(objects, obj_idx)
        return value
    elif _type == list:
        value = []
        for uid in ns_info["NS.objects"]:
            value.append(_parse_object(objects, uid))
        return value
    elif _type == set:
        value = set()
        for uid in ns_info["NS.objects"]:
            value.add(_parse_object(objects, uid))
        return value
    elif _type == datetime.datetime:
        time_since = datetime.datetime(2001, 1, 1)
        value = time_since + datetime.timedelta(seconds=ns_info['NS.time'])
        return value
    elif _type == NSError:
        code = 1
        code = ns_info['NSCode']
        domain = _parse_object(objects, ns_info['NSDomain'])
        user_info = _parse_object(objects, ns_info['NSUserInfo'])
        return NSError(code, domain, user_info)
    elif _type == DTSysmonTapMessage:  # FIXME: some do not have key DTTapMessagePlist
        return _parse_object(objects, ns_info["DTTapMessagePlist"])
    elif issubclass(_type, uuid.UUID):
        return NSUUID.decode(objects, ns_info)
    elif _type == NSIgnore:
        return None
    elif _type == NSNull:
        return NSNull()
    else:
        raise RuntimeError("decode not finished yet")


def objc_decode(data):
    """
    Args:
        data (Union[bytes, dict]):
    Returns:
        Any:
    """
    if isinstance(data, (bytes, bytearray)):
        data = loads(data)
    if not isinstance(data,
                      dict) or data.get('$archiver') != 'NSKeyedArchiver':
        raise InvalidNSKeyedArchiverFormat()

    assert data['$version'] == 100000
    objects = data["$objects"]
    root_index = data["$top"]['root'].data

    return _parse_object(objects, root_index)


def test_objc_encode_decode():
    # yapf: disable
    for value in (
        "hello world",
        {"hello": "world"}, [1, 2, 3],
        {"hello": [1, 2, 3]},
        set([1, 2, 3]),
        {"hello": set([1, 2, 3])},
        uuid.uuid4(),
        NSNull(),
        NSURL(None, "file://abce"),
        {"none-type": None},
        {"hello": {"level2": "hello"}},
        {"hello": {
            "level2": "hello",
            "uuid": uuid.uuid4(),
            "level3": [1, 2, 3],
            "ns-uuid-null": [uuid.uuid4(), NSNull()]}},
        # set([1, {"a": 2}, 3]), # not supported, since dict is not hashable
    ):
        bdata = objc_encode(value)

        try:
            pdata = objc_decode(bdata)
            print("TEST: {:20s}".format(str(value)), end="\t")
            assert pdata == value
            print("[OK]")
        except Exception as e:
            print("Value:", value)
            pprint.pprint(loads(bdata))
            raise

        # data = loads(bdata)
        # pdata = objc_decode(data)
        # assert pdata == value
    # yapf: enable
    # TODO
    # NSDate decode


if __name__ == "__main__":
    test_objc_encode_decode()
