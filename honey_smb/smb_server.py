import hmac
import struct
import time

from scapy.asn1.asn1 import ASN1_STRING
from scapy.automaton import ATMT, Automaton, ObjectPipe
from scapy.compat import Any
from scapy.config import conf
from scapy.contrib.opc_da import AV_PAIR
from scapy.fields import ByteField, PacketListField, StrNullField, LEFieldLenField, XLEShortField, FieldLenField, \
    FlagsField, LEShortField, UUIDField, XLEIntField, ShortField, FieldListField, LEShortEnumField, ConditionalField, \
    ReversePadField, PacketField, IntField, LEIntField, UTCTimeField, XStrLenField, PacketLenField, StrFixedLenField, \
    LEIntEnumField, MultipleTypeField, StrFieldUtf16, ByteEnumField, ScalingField
from scapy.layers.gssapi import GSSAPI_BLOB, SPNEGO_negToken, SPNEGO_Token, SPNEGO_negTokenInit, SPNEGO_MechType, \
    SPNEGO_negTokenResp, SPNEGO_MechListMIC
from scapy.layers.ipsec import hashes
from scapy.layers.netbios import NBTSession
# SMB2 sect 3.3.5.15 + [MS-ERREF]
from scapy.layers.ntlm import NTLM_NEGOTIATE, NTLM_AUTHENTICATE, NTLM_AUTHENTICATE_V2, NTLM_CHALLENGE, NTLM_Header
from scapy.layers.smb import SMBSession_Setup_AndX_Request, SMBSession_Setup_AndX_Response
from scapy.layers.smb import SMBTree_Connect_AndX
from scapy.layers.smb2 import SMB2_Header, SMB_DIALECTS, SMB2_CAPABILITIES
from scapy.layers.smb2 import SMB2_Session_Setup_Request, SMB2_Session_Setup_Response, SMB2_IOCTL_Request, \
    SMB2_Tree_Connect_Request, SMB2_Create_Response, SMB2_FILEID, SMB2_Query_Info_Request, FileStandardInformation, \
    SMB2_Write_Request, SMB2_Write_Response, SMB2_Read_Response, SMB2_Read_Request, SMB2_Close_Request, \
    SMB2_Close_Response, SMB2_Query_Info_Response, SMB2_Create_Request, SMB2_Tree_Connect_Response, SMB2_Error_Response
from scapy.packet import Packet, bind_top_down
from scapy.volatile import RandUUID

STATUS_ERREF = {
    0x00000000: "STATUS_SUCCESS",
    0xC000009A: "STATUS_INSUFFICIENT_RESOURCES",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000128: "STATUS_FILE_CLOSED",  # backup error for older Win versions
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0x80000005: "STATUS_BUFFER_OVERFLOW",
}

SMB_COM = {
    0x00: "SMB_COM_CREATE_DIRECTORY",
    0x01: "SMB_COM_DELETE_DIRECTORY",
    0x02: "SMB_COM_OPEN",
    0x03: "SMB_COM_CREATE",
    0x04: "SMB_COM_CLOSE",
    0x05: "SMB_COM_FLUSH",
    0x06: "SMB_COM_DELETE",
    0x07: "SMB_COM_RENAME",
    0x08: "SMB_COM_QUERY_INFORMATION",
    0x09: "SMB_COM_SET_INFORMATION",
    0x0A: "SMB_COM_READ",
    0x0B: "SMB_COM_WRITE",
    0x0C: "SMB_COM_LOCK_BYTE_RANGE",
    0x0D: "SMB_COM_UNLOCK_BYTE_RANGE",
    0x0E: "SMB_COM_CREATE_TEMPORARY",
    0x0F: "SMB_COM_CREATE_NEW",
    0x10: "SMB_COM_CHECK_DIRECTORY",
    0x11: "SMB_COM_PROCESS_EXIT",
    0x12: "SMB_COM_SEEK",
    0x13: "SMB_COM_LOCK_AND_READ",
    0x14: "SMB_COM_WRITE_AND_UNLOCK",
    0x1A: "SMB_COM_READ_RAW",
    0x1B: "SMB_COM_READ_MPX",
    0x1C: "SMB_COM_READ_MPX_SECONDARY",
    0x1D: "SMB_COM_WRITE_RAW",
    0x1E: "SMB_COM_WRITE_MPX",
    0x1F: "SMB_COM_WRITE_MPX_SECONDARY",
    0x20: "SMB_COM_WRITE_COMPLETE",
    0x21: "SMB_COM_QUERY_SERVER",
    0x22: "SMB_COM_SET_INFORMATION2",
    0x23: "SMB_COM_QUERY_INFORMATION2",
    0x24: "SMB_COM_LOCKING_ANDX",
    0x25: "SMB_COM_TRANSACTION",
    0x26: "SMB_COM_TRANSACTION_SECONDARY",
    0x27: "SMB_COM_IOCTL",
    0x28: "SMB_COM_IOCTL_SECONDARY",
    0x29: "SMB_COM_COPY",
    0x2A: "SMB_COM_MOVE",
    0x2B: "SMB_COM_ECHO",
    0x2C: "SMB_COM_WRITE_AND_CLOSE",
    0x2D: "SMB_COM_OPEN_ANDX",
    0x2E: "SMB_COM_READ_ANDX",
    0x2F: "SMB_COM_WRITE_ANDX",
    0x30: "SMB_COM_NEW_FILE_SIZE",
    0x31: "SMB_COM_CLOSE_AND_TREE_DISC",
    0x32: "SMB_COM_TRANSACTION2",
    0x33: "SMB_COM_TRANSACTION2_SECONDARY",
    0x34: "SMB_COM_FIND_CLOSE2",
    0x35: "SMB_COM_FIND_NOTIFY_CLOSE",
    0x70: "SMB_COM_TREE_CONNECT",
    0x71: "SMB_COM_TREE_DISCONNECT",
    0x72: "SMB_COM_NEGOTIATE",
    0x73: "SMB_COM_SESSION_SETUP_ANDX",
    0x74: "SMB_COM_LOGOFF_ANDX",
    0x75: "SMB_COM_TREE_CONNECT_ANDX",
    0x7E: "SMB_COM_SECURITY_PACKAGE_ANDX",
    0x80: "SMB_COM_QUERY_INFORMATION_DISK",
    0x81: "SMB_COM_SEARCH",
    0x82: "SMB_COM_FIND",
    0x83: "SMB_COM_FIND_UNIQUE",
    0x84: "SMB_COM_FIND_CLOSE",
    0xA0: "SMB_COM_NT_TRANSACT",
    0xA1: "SMB_COM_NT_TRANSACT_SECONDARY",
    0xA2: "SMB_COM_NT_CREATE_ANDX",
    0xA4: "SMB_COM_NT_CANCEL",
    0xA5: "SMB_COM_NT_RENAME",
    0xC0: "SMB_COM_OPEN_PRINT_FILE",
    0xC1: "SMB_COM_WRITE_PRINT_FILE",
    0xC2: "SMB_COM_CLOSE_PRINT_FILE",
    0xC3: "SMB_COM_GET_PRINT_QUEUE",
    0xD8: "SMB_COM_READ_BULK",
    0xD9: "SMB_COM_WRITE_BULK",
    0xDA: "SMB_COM_WRITE_BULK_DATA",
    0xFE: "SMB_COM_INVALID",
    0xFF: "SMB_COM_NO_ANDX_COMMAND",
}


# SMB null (no wordcount)


class SMBSession_Null(Packet):
    fields_desc = [ByteField("WordCount", 0),
                   LEShortField("ByteCount", 0)]


class StrNullFieldUtf16(StrNullField, StrFieldUtf16):
    DELIMITER = b"\x00\x00"
    ALIGNMENT = 2


def _SMBStrNullField(name, default):
    """
    Returns a StrNullField that is either normal or UTF-16 depending
    on the SMB headers.
    """

    def _isUTF16(pkt):
        while not hasattr(pkt, "Flags2") and pkt.underlayer:
            pkt = pkt.underlayer
        return hasattr(pkt, "Flags2") and pkt.Flags2.UNICODE

    return MultipleTypeField(
        [
            (StrNullFieldUtf16(name, default),
             _isUTF16)
        ],
        StrNullField(name, default),
    )


class SMB_Header(Packet):
    name = "SMB 1 Protocol Request Header"
    fields_desc = [StrFixedLenField("Start", b"\xffSMB", 4),
                   ByteEnumField("Command", 0x72, SMB_COM),
                   LEIntEnumField("Status", 0, STATUS_ERREF),
                   FlagsField("Flags", 0x18, 8,
                              ["LOCK_AND_READ_OK",
                               "BUF_AVAIL",
                               "res",
                               "CASE_INSENSITIVE",
                               "CANONICALIZED_PATHS",
                               "OPLOCK",
                               "OPBATCH",
                               "REPLY"]),
                   FlagsField("Flags2", 0x0000, -16,
                              ["LONG_NAMES",
                               "EAS",
                               "SMB_SECURITY_SIGNATURE",
                               "COMPRESSED",
                               "SMB_SECURITY_SIGNATURE_REQUIRED",
                               "res",
                               "IS_LONG_NAME",
                               "res",
                               "res",
                               "res",
                               "REPARSE_PATH",
                               "EXTENDED_SECURITY",
                               "DFS",
                               "PAGING_IO",
                               "NT_STATUS",
                               "UNICODE"]),
                   LEShortField("PIDHigh", 0x0000),
                   StrFixedLenField("SecuritySignature", b"", length=8),
                   LEShortField("Reserved", 0x0),
                   LEShortField("TID", 0),
                   LEShortField("PIDLow", 1),
                   LEShortField("UID", 0),
                   LEShortField("MID", 0)]

    def guess_payload_class(self, payload):
        # type: (bytes) -> Packet
        if not payload:
            return super(SMB_Header, self).guess_payload_class(payload)
        WordCount = ord(payload[:1])
        if self.Command == 0x72:
            if self.Flags.REPLY:
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBNegotiate_Response_Extended_Security
                else:
                    return SMBNegotiate_Response_Security
            else:
                return SMBNegotiate_Request
        elif self.Command == 0x73:
            if WordCount == 0:
                return SMBSession_Null
            if self.Flags.REPLY:
                if WordCount == 0x04:
                    return SMBSession_Setup_AndX_Response_Extended_Security
                elif WordCount == 0x03:
                    return SMBSession_Setup_AndX_Response
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBSession_Setup_AndX_Response_Extended_Security
                else:
                    return SMBSession_Setup_AndX_Response
            else:
                if WordCount == 0x0C:
                    return SMBSession_Setup_AndX_Request_Extended_Security
                elif WordCount == 0x0D:
                    return SMBSession_Setup_AndX_Request
                if self.Flags2.EXTENDED_SECURITY:
                    return SMBSession_Setup_AndX_Request_Extended_Security
                else:
                    return SMBSession_Setup_AndX_Request
        elif self.Command == 0x25:
            return SMBNetlogon_Protocol_Response_Header
        return super(SMB_Header, self).guess_payload_class(payload)

    def answers(self, pkt):
        return SMB_Header in pkt


# SMB NetLogon Response Header


class SMBNetlogon_Protocol_Response_Header(Packet):
    name = "SMBNetlogon Protocol Response Header"
    fields_desc = [ByteField("WordCount", 17),
                   LEShortField("TotalParamCount", 0),
                   LEShortField("TotalDataCount", 112),
                   LEShortField("MaxParamCount", 0),
                   LEShortField("MaxDataCount", 0),
                   ByteField("MaxSetupCount", 0),
                   ByteField("unused2", 0),
                   LEShortField("Flags3", 0),
                   ByteField("TimeOut1", 0xe8),
                   ByteField("TimeOut2", 0x03),
                   LEShortField("unused3", 0),
                   LEShortField("unused4", 0),
                   LEShortField("ParamCount2", 0),
                   LEShortField("ParamOffset", 0),
                   LEShortField("DataCount", 112),
                   LEShortField("DataOffset", 92),
                   ByteField("SetupCount", 3),
                   ByteField("unused5", 0)]


bind_top_down(SMB_Header, SMBNetlogon_Protocol_Response_Header,
              Command=0x25)

# SMB sect 2.2.4.6.1


class SMBSession_Setup_AndX_Request_Extended_Security(Packet):
    name = "Session Setup AndX Extended Security Request (SMB)"
    WordCount = 0x0C
    fields_desc = SMBSession_Setup_AndX_Request.fields_desc[:8] + [
        LEFieldLenField("SecurityBlobLength", None,
                        length_of="SecurityBlob"),
    ] + SMBSession_Setup_AndX_Request.fields_desc[10:12] + [
                      LEShortField("ByteCount", None),
                      PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                                     length_from=lambda x: x.SecurityBlobLength),
                      ReversePadField(
                          _SMBStrNullField("NativeOS", "Windows 4.0"),
                          2, b"\0",
                      ),
                      _SMBStrNullField("NativeLanMan", "Windows 4.0"),
                  ]

    def post_build(self, pkt, pay):
        if self.ByteCount is None:
            pkt = pkt[:25] + struct.pack("<H", len(pkt) - 27) + pkt[27:]
        return pkt + pay


# SMB sect 2.2.4.6.2
# uWu


class SMBSession_Setup_AndX_Response_Extended_Security(SMBSession_Setup_AndX_Response):  # noqa: E501
    name = "Session Setup AndX Extended Security Response (SMB)"
    WordCount = 0x4
    fields_desc = (
        SMBSession_Setup_AndX_Response.fields_desc[:5] +
        [SMBSession_Setup_AndX_Request_Extended_Security.fields_desc[8]] +
        SMBSession_Setup_AndX_Request_Extended_Security.fields_desc[11:]
    )

    def post_build(self, pkt, pay):
        if self.ByteCount is None:
            pkt = pkt[:9] + struct.pack("<H", len(pkt) - 11) + pkt[11:]
        return super(
            SMBSession_Setup_AndX_Response_Extended_Security,
            self
        ).post_build(pkt, pay)


bind_top_down(SMB_Header, SMBSession_Setup_AndX_Response_Extended_Security,
              Command=0x73, Flags=0x80, Flags2=0x800)


class SMB_Dialect(Packet):
    name = "SMB Dialect"
    fields_desc = [ByteField("BufferFormat", 0x02),
                   StrNullField("DialectString", "NT LM 0.12")]

    def default_payload_class(self, payload):
        return conf.padding_layer


class SMBNegotiate_Request(Packet):
    name = "SMB Negotiate Request"
    fields_desc = [ByteField("WordCount", 0),
                   LEFieldLenField("ByteCount", None, length_of="Dialects"),
                   PacketListField(
                       "Dialects", [SMB_Dialect()], SMB_Dialect,
                       length_from=lambda pkt: pkt.ByteCount)]


# sect 2.2.3

# EnumField
SMB2_NEGOTIATE_CONTEXT_TYPES = {
    0x0001: 'SMB2_PREAUTH_INTEGRITY_CAPABILITIES',
    0x0002: 'SMB2_ENCRYPTION_CAPABILITIES',
    0x0003: 'SMB2_COMPRESSION_CAPABILITIES',
    0x0005: 'SMB2_NETNAME_NEGOTIATE_CONTEXT_ID',
    0x0006: 'SMB2_TRANSPORT_CAPABILITIES',
    0x0007: 'SMB2_RDMA_TRANSFORM_CAPABILITIES',
    0x0008: 'SMB2_SIGNING_CAPABILITIES',
}


class SMB2_Negotiate_Context(Packet):
    name = "SMB2 Negotiate Context"
    fields_desc = [
        LEShortEnumField("ContextType", 0x0, SMB2_NEGOTIATE_CONTEXT_TYPES),
        FieldLenField("DataLength", 0x0, fmt="<H", length_of="Data"),
        IntField("Reserved", 0),
    ]


class SMB2_Negotiate_Protocol_Request(Packet):
    name = "SMB2 Negotiate Protocol Request"
    fields_desc = [
        XLEShortField("StructureSize", 0x24),
        FieldLenField(
            "DialectCount", None,
            fmt="<H",
            count_of="Dialects"
        ),
        # SecurityMode
        FlagsField("SecurityMode", 0, -16, {
            0x01: "SMB2_NEGOTIATE_SIGNING_ENABLED",
            0x02: "SMB2_NEGOTIATE_SIGNING_REQUIRED",
        }),
        LEShortField("Reserved", 0),
        # Capabilities
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        UUIDField("ClientGUID", 0x0, uuid_fmt=UUIDField.FORMAT_LE),
        # XXX TODO If we ever want to properly dissect the offsets, we have
        # a _NTLMPayloadField in scapy/layers/ntlm.py that does precisely that
        XLEIntField("NegotiateContextOffset", 0x0),
        FieldLenField(
            "NegotiateCount", None,
            fmt="<H",
            count_of="NegotiateContexts"
        ),
        ShortField("Reserved2", 0),
        FieldListField(
            "Dialects", [0x0202],
            LEShortEnumField("", 0x0, SMB_DIALECTS),
            count_from=lambda pkt: pkt.DialectCount
        ),
        # Field only exists if Dialects contains 0x0311
        # Each negotiate context must be 8-byte aligned
        ConditionalField(
            FieldListField(
                "NegotiateContexts", [],
                ReversePadField(
                    PacketField("Context", None, SMB2_Negotiate_Context), 8
                ), count_from=lambda pkt: pkt.NegotiateCount
            ), lambda x: 0x0311 in x.Dialects
        ),
    ]


def _len(pkt, name):
    """
    Returns the length of a field, works with Unicode strings.
    """
    fld, v = pkt.getfield_and_val(name)
    return len(fld.addfield(pkt, v, b""))


class _SMBNegotiate_Response(Packet):
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and len(_pkt) >= 2:
            # Yes this is inspired by
            # https://github.com/wireshark/wireshark/blob/925e01b23fd5aad2fa929fafd894128a88832e74/epan/dissectors/packet-smb.c#L2902
            wc = struct.unpack("<H", _pkt[:1])
            # dialect = struct.unpack("<H", _pkt[1:3])
            if wc == 1:
                # Core Protocol
                return SMBNegotiate_Response_NoSecurity
            elif wc == 0xD:
                # LAN Manager 1.0 - LAN Manager 2.1
                # TODO
                pass
            elif wc == 0x11:
                # NT LAN Manager
                return cls
        return cls


_SMB_ServerCapabilities = [
    "RAW_MODE",
    "MPX_MODE",
    "UNICODE",
    "LARGE_FILES",
    "NT_SMBS",
    "RPC_REMOTE_APIS",
    "STATUS32",
    "LEVEL_II_OPLOCKS",
    "LOCK_AND_READ",
    "NT_FIND",
    "res", "res",
    "DFS",
    "INFOLEVEL_PASSTHRU",
    "LARGE_READX",
    "LARGE_WRITEX",
    "LWIO",
    "res", "res", "res", "res", "res", "res",
    "UNIX",
    "res",
    "COMPRESSED_DATA",
    "res", "res", "res",
    "DYNAMIC_REAUTH",
    "PERSISTENT_HANDLES",
    "EXTENDED_SECURITY"
]


# CIFS sect 2.2.4.52.2
class SMBNegotiate_Response_NoSecurity(_SMBNegotiate_Response):
    name = "SMB Negotiate No-Security Response (CIFS)"
    fields_desc = [ByteField("WordCount", 0x1),
                   LEShortField("DialectIndex", 7),
                   FlagsField("SecurityMode", 0x03, 8,
                              ["USER_SECURITY",
                               "ENCRYPT_PASSWORDS",
                               "SECURITY_SIGNATURES_ENABLED",
                               "SECURITY_SIGNATURES_REQUIRED"]),
                   LEShortField("MaxMpxCount", 50),
                   LEShortField("MaxNumberVC", 1),
                   LEIntField("MaxBufferSize", 16144),  # Windows: 4356
                   LEIntField("MaxRawSize", 65536),
                   LEIntField("SessionKey", 0x0000),
                   FlagsField("ServerCapabilities", 0xf3f9, -32,
                              _SMB_ServerCapabilities),
                   UTCTimeField("ServerTime", None, fmt="<Q",
                                epoch=[1601, 1, 1, 0, 0, 0],
                                custom_scaling=1e7),
                   ScalingField("ServerTimeZone", 0x3c, fmt="<h",
                                unit="min-UTC"),
                   FieldLenField("ChallengeLength", None,
                                 # aka EncryptionKeyLength
                                 length_of="Challenge", fmt="<B"),
                   LEFieldLenField("ByteCount", None, length_of="DomainName",
                                   adjust=lambda pkt, x: x +
                                                         len(pkt.Challenge)),
                   XStrLenField("Challenge", b"",  # aka EncryptionKey
                                length_from=lambda pkt: pkt.ChallengeLength),
                   StrNullField("DomainName", "WORKGROUP")]


# SMB sect 2.2.4.5.2.1


class SMBNegotiate_Response_Extended_Security(_SMBNegotiate_Response):
    name = "SMB Negotiate Extended Security Response (SMB)"
    WordCount = 0x11
    fields_desc = SMBNegotiate_Response_NoSecurity.fields_desc[:12] + [
        LEFieldLenField("ByteCount", None, length_of="SecurityBlob",
                        adjust=lambda _, x: x + 16),
        SMBNegotiate_Response_NoSecurity.fields_desc[13],
        UUIDField("GUID", None, uuid_fmt=UUIDField.FORMAT_LE),
        PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                       length_from=lambda x: x.ByteCount - 16)
    ]


# SMB sect 2.2.4.5.2.2


class SMBNegotiate_Response_Security(_SMBNegotiate_Response):
    name = "SMB Negotiate Non-Extended Security Response (SMB)"
    WordCount = 0x11
    fields_desc = SMBNegotiate_Response_NoSecurity.fields_desc[:12] + [
        LEFieldLenField("ByteCount", None, length_of="DomainName",
                        adjust=lambda pkt, x: x + 2 + _len(pkt, "Challenge") +
                                              _len(pkt, "ServerName")),
        XStrLenField("Challenge", b"",  # aka EncryptionKey
                     length_from=lambda pkt: pkt.ChallengeLength),
        _SMBStrNullField("DomainName", "WORKGROUP"),
        _SMBStrNullField("ServerName", "RMFF1")
    ]


class SMB2_Negotiate_Protocol_Response(Packet):
    name = "SMB2 Negotiate Protocol Response"
    fields_desc = [
        XLEShortField("StructureSize", 0x41),
        FlagsField("SecurityMode", 0, -16, {
            0x1: "Signing Required",
            0x2: "Signing Enabled",
        }),
        LEShortEnumField("DialectRevision", 0x0, SMB_DIALECTS),
        FieldLenField(
            "NegotiateCount", None,
            fmt="<H",
            count_of="NegotiateContexts"
        ),
        UUIDField("GUID", 0x0,
                  uuid_fmt=UUIDField.FORMAT_LE),
        # Capabilities
        FlagsField("Capabilities", 0, -32, SMB2_CAPABILITIES),
        LEIntField("MaxTransactionSize", 65536),
        LEIntField("MaxReadSize", 65536),
        LEIntField("MaxWriteSize", 65536),
        UTCTimeField("ServerTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        UTCTimeField("ServerStartTime", None, fmt="<Q",
                     epoch=[1601, 1, 1, 0, 0, 0],
                     custom_scaling=1e7),
        FieldLenField(
            "SecurityBlobOffset", None,
            fmt="<H",
            length_of="SecurityBlobPad",
            adjust=lambda pkt, x: x + 0x80
        ),
        FieldLenField(
            "SecurityBlobLength", None,
            fmt="<H",
            length_of="SecurityBlob"
        ),
        XLEIntField("NegotiateContextOffset", 0),
        XStrLenField("SecurityBlobPad", "",
                     length_from=lambda pkt: pkt.SecurityBlobOffset - 0x80),
        PacketLenField("SecurityBlob", None, GSSAPI_BLOB,
                       length_from=lambda x: x.SecurityBlobLength),
        # Field only exists if Dialect is 0x0311
        # Each negotiate context must be 8-byte aligned
        ConditionalField(
            FieldListField(
                "NegotiateContexts", [],
                ReversePadField(
                    PacketField("Context", None, SMB2_Negotiate_Context), 8
                ), count_from=lambda pkt: pkt.NegotiateCount
            ), lambda x: x.DialectRevision == 0x0311
        ),
    ]


# Answering machine


class _NTLM_Automaton(Automaton):
    def __init__(self, sock, **kwargs):
        # type: (StreamSocket, Any) -> None
        self.token_pipe = ObjectPipe()
        self.values = {}
        for key, dflt in [("DROP_MIC_v1", False), ("DROP_MIC_v2", False)]:
            setattr(self, key, kwargs.pop(key, dflt))
        self.DROP_MIC = self.DROP_MIC_v1 or self.DROP_MIC_v2
        super(_NTLM_Automaton, self).__init__(
            recvsock=lambda **kwargs: sock,
            ll=lambda **kwargs: sock,
            **kwargs
        )

    def _get_token(self, token):
        if not token:
            return None, None, None, None

        negResult = None
        MIC = None
        rawToken = False

        if isinstance(token, bytes):
            # SMB 1 - non extended
            return (token, None, None, True)
        if isinstance(token, (NTLM_NEGOTIATE,
                              NTLM_CHALLENGE,
                              NTLM_AUTHENTICATE,
                              NTLM_AUTHENTICATE_V2)):
            ntlm = token
            rawToken = True
        if isinstance(token, GSSAPI_BLOB):
            token = token.innerContextToken
        if isinstance(token, SPNEGO_negToken):
            token = token.token
        if hasattr(token, "mechListMIC") and token.mechListMIC:
            MIC = token.mechListMIC.value
        if hasattr(token, "negResult"):
            negResult = token.negResult
        try:
            ntlm = token.mechToken
        except AttributeError:
            ntlm = token.responseToken
        if isinstance(ntlm, SPNEGO_Token):
            ntlm = ntlm.value
        if isinstance(ntlm, ASN1_STRING):
            ntlm = NTLM_Header(ntlm.val)
        if isinstance(ntlm, conf.raw_layer):
            ntlm = NTLM_Header(ntlm.load)
        if self.DROP_MIC_v1 or self.DROP_MIC_v2:
            if isinstance(ntlm, NTLM_AUTHENTICATE):
                ntlm.MIC = b"\0" * 16
                ntlm.NtChallengeResponseLen = None
                ntlm.NtChallengeResponseMaxLen = None
                ntlm.EncryptedRandomSessionKeyBufferOffset = None
                if self.DROP_MIC_v2:
                    ChallengeResponse = next(
                        v[1] for v in ntlm.Payload
                        if v[0] == 'NtChallengeResponse'
                    )
                    i = next(
                        i for i, k in enumerate(ChallengeResponse.AvPairs)
                        if k.AvId == 0x0006
                    )
                    ChallengeResponse.AvPairs.insert(
                        i + 1,
                        AV_PAIR(AvId="MsvAvFlags", Value=0)
                    )
        return ntlm, negResult, MIC, rawToken

    def received_ntlm_token(self, ntlm):
        self.token_pipe.send(ntlm)

    def get(self, attr, default=None):
        if default is not None:
            return self.values.get(attr, default)
        return self.values[attr]

    def end(self):
        self.listen_sock.close()
        self.stop()


def HMAC_MD5(key, data):
    h = hmac.HMAC(key, hashes.MD5())
    h.update(data)
    return h.finalize()


def RC4K(key, data):
    """Alleged RC4"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def NTLMv2_ComputeSessionBaseKey(ResponseKeyNT, NTProofStr):
    return HMAC_MD5(ResponseKeyNT, NTProofStr)


class NTLM_Server(_NTLM_Automaton):
    """
    A class to overload to create a server automaton when using
    NTLM.
    """
    port = 445
    cls = conf.raw_layer

    def __init__(self, *args, **kwargs):
        self.cli_atmt = None
        self.cli_values = dict()
        self.ntlm_values = kwargs.pop("NTLM_VALUES", dict())
        self.ntlm_state = 0
        self.IDENTITIES = kwargs.pop("IDENTITIES", None)
        self.SigningSessionKey = None
        super(NTLM_Server, self).__init__(*args, **kwargs)

    def bind(self, cli_atmt):
        # type: (NTLM_Client) -> None
        self.cli_atmt = cli_atmt

    def get_token(self):
        from random import randint
        if self.cli_atmt:
            return self.cli_atmt.token_pipe.recv()
        elif self.ntlm_state == 0:
            self.ntlm_state = 1
            return NTLM_CHALLENGE(
                ServerChallenge=self.ntlm_values.get(
                    "ServerChallenge", struct.pack("<Q", randint(0, 2 ** 64))),
                MessageType=2,
                NegotiateFlags=self.ntlm_values.get(
                    "NegotiateFlags", 0xe2898215),
                ProductMajorVersion=self.ntlm_values.get(
                    "ProductMajorVersion", 10),
                ProductMinorVersion=self.ntlm_values.get(
                    "ProductMinorVersion", 0),
                Payload=[
                    ('TargetName', self.ntlm_values.get("TargetName", "")),
                    ('TargetInfo', [
                        # MsvAvNbComputerName
                        AV_PAIR(AvId=1, Value=self.ntlm_values.get(
                            "NetbiosComputerName", "")),
                        #  "T1-SRV-DHCP"),
                        # MsvAvNbDomainName
                        AV_PAIR(AvId=2, Value=self.ntlm_values.get(
                            "NetbiosDomainName", "")),
                        #  "TESTDOMAIN"),
                        # MsvAvDnsComputerName
                        AV_PAIR(AvId=3, Value=self.ntlm_values.get(
                            "DnsComputerName", "")),
                        # "T1-SRV-DHCP.TESTDOMAIN.local"),
                        # MsvAvDnsDomainName
                        AV_PAIR(AvId=4, Value=self.ntlm_values.get(
                            "DnsDomainName", "")),
                        # TESTDOMAIN.local"),
                        # MsvAvDnsTreeName
                        AV_PAIR(AvId=5, Value=self.ntlm_values.get(
                            "DnsTreeName", "")),
                        # TESTDOMAIN.local"),
                        # MsvAvTimestamp
                        AV_PAIR(AvId=7, Value=self.ntlm_values.get(
                            "Timestamp", 0.0)),
                        # MsvAvEOL
                        AV_PAIR(AvId=0),
                    ]),
                ]
            ), None, None, False
        elif self.ntlm_state == 1:
            self.ntlm_state = 0
            return None, 0, None, False

    def received_ntlm_token(self, ntlm_tuple):
        ntlm = ntlm_tuple[0]
        if isinstance(ntlm, NTLM_AUTHENTICATE_V2) and self.IDENTITIES:
            username = ntlm.UserName
            if username in self.IDENTITIES:
                SessionBaseKey = NTLMv2_ComputeSessionBaseKey(
                    self.IDENTITIES[username],
                    ntlm.NtChallengeResponse.NTProofStr
                )
                # [MS-NLMP] sect 3.2.5.1.2
                KeyExchangeKey = SessionBaseKey  # Only true for NTLMv2
                if ntlm.NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH:
                    ExportedSessionKey = RC4K(
                        KeyExchangeKey,
                        ntlm.EncryptedRandomSessionKey
                    )
                else:
                    ExportedSessionKey = KeyExchangeKey
                self.SigningSessionKey = ExportedSessionKey  # For SMB
        super(NTLM_Server, self).received_ntlm_token(ntlm_tuple)

    def set_cli(self, attr, value):
        if self.cli_atmt:
            self.cli_atmt.values[attr] = value
        else:
            self.cli_values[attr] = value

    def echo(self, pkt):
        if self.cli_atmt:
            return self.cli_atmt.send(pkt)

    def start_client(self, **kwargs):
        assert (self.cli_atmt), "Cannot start NTLM client: not provided"
        self.cli_atmt.client_pipe.send(kwargs)


class NTLM_SMB_Server(NTLM_Server, Automaton):
    port = 445
    cls = NBTSession

    def __init__(self, *args, **kwargs):
        self.CLIENT_PROVIDES_NEGOEX = kwargs.pop(
            "CLIENT_PROVIDES_NEGOEX", False)
        self.ECHO = kwargs.pop("ECHO", False)
        self.SERVE_FILES = kwargs.pop("SERVE_FILES", [])
        self.ANONYMOUS_LOGIN = kwargs.pop("ANONYMOUS_LOGIN", False)
        self.GUEST_LOGIN = kwargs.pop("GUEST_LOGIN", False)
        self.PASS_NEGOEX = kwargs.pop("PASS_NEGOEX", False)
        self.EXTENDED_SECURITY = kwargs.pop("EXTENDED_SECURITY", True)
        self.ALLOW_SMB2 = kwargs.pop("ALLOW_SMB2", True)
        self.REQUIRE_SIGNATURE = kwargs.pop("REQUIRE_SIGNATURE", False)
        self.REAL_HOSTNAME = kwargs.pop(
            "REAL_HOSTNAME", None)  # Compulsory for SMB1 !!!
        assert self.ALLOW_SMB2 or \
               self.REAL_HOSTNAME, "SMB1 requires REAL_HOSTNAME !"
        # Session information
        self.SMB2 = False
        self.Dialect = None
        super(NTLM_SMB_Server, self).__init__(*args, **kwargs)

    def send(self, pkt):
        if self.Dialect and self.SigningSessionKey:
            if isinstance(pkt.payload, SMB2_Header):
                # Sign SMB2 !
                smb = pkt[SMB2_Header]
                smb.Flags += "SMB2_FLAGS_SIGNED"
                smb.sign(self.Dialect, self.SigningSessionKey)
        return super(NTLM_SMB_Server, self).send(pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        self.authenticated = False
        assert \
            not self.ECHO or self.cli_atmt, \
            "Cannot use ECHO without binding to a client !"
        assert \
            not (self.cli_atmt and self.SERVE_FILES), \
            "Cannot use SERVE_FILES if a client is bound !"

    @ATMT.receive_condition(BEGIN)
    def received_negotiate(self, pkt):
        if SMBNegotiate_Request in pkt:
            if self.cli_atmt:
                self.start_client()
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.receive_condition(BEGIN)
    def received_negotiate_smb2_begin(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            self.SMB2 = True
            if self.cli_atmt:
                self.start_client(
                    CONTINUE_SMB2=True,
                    SMB2_INIT_PARAMS={
                        "ClientGUID": pkt.ClientGUID
                    }
                )
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2_begin)
    def on_negotiate_smb2_begin(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.action(received_negotiate)
    def on_negotiate(self, pkt):
        if self.CLIENT_PROVIDES_NEGOEX:
            negoex_token, _, _, _ = self.get_token()
        else:
            negoex_token = None
        if not self.SMB2 and not self.get("GUID", 0):
            self.EXTENDED_SECURITY = False
        # Build negotiate response
        DialectIndex = None
        DialectRevision = None
        if SMB2_Negotiate_Protocol_Request in pkt:
            # SMB2
            DialectRevisions = pkt[SMB2_Negotiate_Protocol_Request].Dialects
            DialectRevisions.sort()
            DialectRevision = DialectRevisions[0]
            if DialectRevision >= 0x300:  # SMB3
                raise ValueError(
                    "SMB client requires SMB3 which is unimplemented.")
        else:
            DialectIndexes = [
                x.DialectString for x in pkt[SMBNegotiate_Request].Dialects
            ]
            if self.ALLOW_SMB2:
                # Find a value matching SMB2, fallback to SMB1
                for key, rev in [(b"SMB 2.???", 0x02ff),
                                 (b"SMB 2.002", 0x0202)]:
                    try:
                        DialectIndex = DialectIndexes.index(key)
                        DialectRevision = rev
                        self.SMB2 = True
                        break
                    except ValueError:
                        pass
                else:
                    DialectIndex = DialectIndexes.index(b"NT LM 0.12")
            else:
                # Enforce SMB1
                DialectIndex = DialectIndexes.index(b"NT LM 0.12")
        if DialectRevision and DialectRevision & 0xff != 0xff:
            # Version isn't SMB X.???
            self.Dialect = DialectRevision
        cls = None
        if self.SMB2:
            # SMB2
            cls = SMB2_Negotiate_Protocol_Response
            self.smb_header = NBTSession() / SMB2_Header(
                CreditsRequested=1,
            )
            if SMB2_Negotiate_Protocol_Request in pkt:
                self.smb_header.MID = pkt.MID
                self.smb_header.TID = pkt.TID
                self.smb_header.AsyncId = pkt.AsyncId
                self.smb_header.SessionId = pkt.SessionId
        else:
            # SMB1
            self.smb_header = NBTSession() / SMB_Header(
                Flags="REPLY+CASE_INSENSITIVE+CANONICALIZED_PATHS",
                Flags2=(
                    "LONG_NAMES+EAS+NT_STATUS+SMB_SECURITY_SIGNATURE+"
                    "UNICODE+EXTENDED_SECURITY"
                ),
                TID=pkt.TID,
                MID=pkt.MID,
                UID=pkt.UID,
                PIDLow=pkt.PIDLow
            )
            if self.EXTENDED_SECURITY:
                cls = SMBNegotiate_Response_Extended_Security
            else:
                cls = SMBNegotiate_Response_Security
        if self.SMB2:
            # SMB2
            resp = self.smb_header.copy() / cls(
                DialectRevision=DialectRevision,
                Capabilities="DFS",
                SecurityMode=3 if self.REQUIRE_SIGNATURE else 0,
                # self.get("SecurityMode", 1),
                ServerTime=self.get("ServerTime", time.time() + 11644473600),
                ServerStartTime=0,
                MaxTransactionSize=65536,
                MaxReadSize=65536,
                MaxWriteSize=65536,
            )
        else:
            # SMB1
            resp = self.smb_header.copy() / cls(
                DialectIndex=DialectIndex,
                ServerCapabilities=(
                    "UNICODE+LARGE_FILES+NT_SMBS+RPC_REMOTE_APIS+STATUS32+"
                    "LEVEL_II_OPLOCKS+LOCK_AND_READ+NT_FIND+"
                    "LWIO+INFOLEVEL_PASSTHRU+LARGE_READX+LARGE_WRITEX"
                ),
                SecurityMode=(
                    3 if self.REQUIRE_SIGNATURE
                    else self.get("SecurityMode", 1)),
                ServerTime=self.get("ServerTime"),
                ServerTimeZone=self.get("ServerTimeZone")
            )
            if self.EXTENDED_SECURITY:
                resp.ServerCapabilities += "EXTENDED_SECURITY"
        if self.EXTENDED_SECURITY or self.SMB2:
            # Extended SMB1 / SMB2
            # Add security blob
            resp.SecurityBlob = GSSAPI_BLOB(
                innerContextToken=SPNEGO_negToken(
                    token=SPNEGO_negTokenInit(
                        mechTypes=[
                            # NEGOEX - Optional. See below
                            # NTLMSSP
                            SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.10")],

                    )
                )
            )
            resp.GUID = self.get("GUID", RandUUID())
            if self.PASS_NEGOEX:  # NEGOEX handling
                # NOTE: NegoEX has an effect on how the SecurityContext is
                # initialized, as detailed in [MS-AUTHSOD] sect 3.3.2
                # But the format that the Exchange token uses appears not to
                # be documented :/
                resp.SecurityBlob.innerContextToken.token.mechTypes.insert(
                    0,
                    # NEGOEX
                    SPNEGO_MechType(oid="1.3.6.1.4.1.311.2.2.30"),
                )
                resp.SecurityBlob.innerContextToken.token.mechToken = SPNEGO_Token(  # noqa: E501
                    value=negoex_token
                )
        else:
            # Non-extended SMB1
            resp.Challenge = self.get("Challenge")
            resp.DomainName = self.get("DomainName")
            resp.ServerName = self.get("ServerName")
            resp.Flags2 -= "EXTENDED_SECURITY"
        if not self.SMB2:
            resp[SMB_Header].Flags2 = resp[SMB_Header].Flags2 - \
                                      "SMB_SECURITY_SIGNATURE" + \
                                      "SMB_SECURITY_SIGNATURE_REQUIRED+IS_LONG_NAME"
        self.send(resp)

    @ATMT.state()
    def NEGOTIATED(self):
        pass

    @ATMT.receive_condition(NEGOTIATED)
    def received_negotiate_smb2(self, pkt):
        if SMB2_Negotiate_Protocol_Request in pkt:
            raise self.NEGOTIATED().action_parameters(pkt)

    @ATMT.action(received_negotiate_smb2)
    def on_negotiate_smb2(self, pkt):
        self.on_negotiate(pkt)

    @ATMT.receive_condition(NEGOTIATED)
    def receive_setup_andx_request(self, pkt):
        if SMBSession_Setup_AndX_Request_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Request in pkt:
            # SMB1
            if SMBSession_Setup_AndX_Request_Extended_Security in pkt:
                # Extended
                ntlm_tuple = self._get_token(
                    pkt.SecurityBlob
                )
            else:
                # Non-extended
                self.set_cli("AccountName", pkt.AccountName)
                self.set_cli("PrimaryDomain",
                             pkt.PrimaryDomain)
                self.set_cli("Path", pkt.Path)
                self.set_cli("Service", pkt.Service)
                ntlm_tuple = self._get_token(
                    pkt[SMBSession_Setup_AndX_Request].UnicodePassword
                )
            self.set_cli("VCNumber", pkt.VCNumber)
            self.set_cli("SecuritySignature", pkt.SecuritySignature)
            self.set_cli("UID", pkt.UID)
            self.set_cli("MID", pkt.MID)
            self.set_cli("TID", pkt.TID)
            self.received_ntlm_token(ntlm_tuple)
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt)
        elif SMB2_Session_Setup_Request in pkt:
            # SMB2
            ntlm_tuple = self._get_token(pkt.SecurityBlob)
            self.set_cli("SecuritySignature", pkt.SecuritySignature)
            self.set_cli("MID", pkt.MID)
            self.set_cli("TID", pkt.TID)
            self.set_cli("AsyncId", pkt.AsyncId)
            self.set_cli("SessionId", pkt.SessionId)
            self.set_cli("SecurityMode", pkt.SecurityMode)
            self.received_ntlm_token(ntlm_tuple)
            raise self.RECEIVED_SETUP_ANDX_REQUEST().action_parameters(pkt)

    @ATMT.state()
    def RECEIVED_SETUP_ANDX_REQUEST(self):
        pass

    @ATMT.action(receive_setup_andx_request)
    def on_setup_andx_request(self, pkt):
        ntlm_token, negResult, MIC, rawToken = ntlm_tuple = self.get_token()
        # rawToken == whether the GSSAPI ASN.1 wrapper is used
        # typically, when a SMB session **falls back** to NTLM, no
        # wrapper is used
        if SMBSession_Setup_AndX_Request_Extended_Security in pkt or \
                SMBSession_Setup_AndX_Request in pkt or \
                SMB2_Session_Setup_Request in pkt:
            if SMB2_Session_Setup_Request in pkt:
                # SMB2
                self.smb_header.MID = self.get(
                    "MID", self.smb_header.MID + 1)
                self.smb_header.TID = self.get(
                    "TID", self.smb_header.TID)
                if self.smb_header.Flags.SMB2_FLAGS_ASYNC_COMMAND:
                    self.smb_header.AsyncId = self.get(
                        "AsyncId", self.smb_header.AsyncId)
                self.smb_header.SessionId = self.get(
                    "SessionId", self.smb_header.SessionId)
            else:
                # SMB1
                self.smb_header.UID = self.get("UID")
                self.smb_header.MID = self.get("MID")
                self.smb_header.TID = self.get("TID")
            if ntlm_tuple == (None, None, None, None):
                # Error
                if SMB2_Session_Setup_Request in pkt:
                    # SMB2
                    resp = self.smb_header.copy() / \
                           SMB2_Session_Setup_Response()
                else:
                    # SMB1
                    resp = self.smb_header.copy() / SMBSession_Null()
                resp.Status = self.get("Status", 0xc000006d)
            else:
                # Negotiation
                if SMBSession_Setup_AndX_Request_Extended_Security in pkt or \
                        SMB2_Session_Setup_Request in pkt:
                    # SMB1 extended / SMB2
                    if SMB2_Session_Setup_Request in pkt:
                        # SMB2
                        resp = self.smb_header.copy() / \
                               SMB2_Session_Setup_Response()
                        if self.GUEST_LOGIN:
                            resp.SessionFlags = "IS_GUEST"
                        if self.ANONYMOUS_LOGIN:
                            resp.SessionFlags = "IS_NULL"
                    else:
                        # SMB1 extended
                        resp = self.smb_header.copy() / \
                               SMBSession_Setup_AndX_Response_Extended_Security(
                                   NativeOS=self.get("NativeOS"),
                                   NativeLanMan=self.get("NativeLanMan")
                               )
                        if self.GUEST_LOGIN:
                            resp.Action = "SMB_SETUP_GUEST"
                    if not ntlm_token:
                        # No token (e.g. accepted)
                        resp.SecurityBlob = SPNEGO_negToken(
                            token=SPNEGO_negTokenResp(
                                negResult=negResult,
                            )
                        )
                        if MIC and not self.DROP_MIC:  # Drop the MIC?
                            resp.SecurityBlob.token.mechListMIC = SPNEGO_MechListMIC(  # noqa: E501
                                value=MIC
                            )
                        if negResult == 0:
                            self.authenticated = True
                    elif isinstance(ntlm_token, NTLM_CHALLENGE) \
                            and not rawToken:
                        resp.SecurityBlob = SPNEGO_negToken(
                            token=SPNEGO_negTokenResp(
                                negResult=1,
                                supportedMech=SPNEGO_MechType(
                                    # NTLMSSP
                                    oid="1.3.6.1.4.1.311.2.2.10"),
                                responseToken=SPNEGO_Token(
                                    value=ntlm_token
                                )
                            )
                        )
                    else:
                        # Token is raw or unknown
                        resp.SecurityBlob = ntlm_token
                elif SMBSession_Setup_AndX_Request in pkt:
                    # Non-extended
                    resp = self.smb_header.copy() / \
                           SMBSession_Setup_AndX_Response(
                               NativeOS=self.get("NativeOS"),
                               NativeLanMan=self.get("NativeLanMan")
                           )
                resp.Status = self.get(
                    "Status", 0x0 if self.authenticated else 0xc0000016)
        self.send(resp)

    @ATMT.condition(RECEIVED_SETUP_ANDX_REQUEST)
    def wait_for_next_request(self):
        if self.authenticated:
            raise self.AUTHENTICATED()
        else:
            raise self.NEGOTIATED()

    @ATMT.state()
    def AUTHENTICATED(self):
        """Dev: overload this"""
        pass

    @ATMT.condition(AUTHENTICATED, prio=0)
    def should_serve(self):
        if self.SERVE_FILES:
            # Serve files
            raise self.SERVING()

    @ATMT.condition(AUTHENTICATED, prio=1)
    def should_end(self):
        if not self.ECHO:
            # Close connection
            raise self.END()

    @ATMT.receive_condition(AUTHENTICATED, prio=2)
    def receive_packet_echo(self, pkt):
        if self.ECHO:
            raise self.AUTHENTICATED().action_parameters(pkt)

    def _response_validate_negotiate_info(self):
        pkt = self.smb_header.copy() / \
              SMB2_Error_Response(ErrorData=b"\xff")
        pkt.Status = "STATUS_NOT_SUPPORTED"
        pkt.Command = "SMB2_IOCTL"
        self.send(pkt)

    @ATMT.action(receive_packet_echo)
    def pass_packet(self, pkt):
        # Pre-process some of the data if possible
        pkt.show()
        if not self.SMB2:
            # SMB1 - no signature (disabled by our implementation)
            if SMBTree_Connect_AndX in pkt and self.REAL_HOSTNAME:
                pkt.LENGTH = None
                pkt.ByteCount = None
                pkt.Path = (
                        "\\\\%s\\" % self.REAL_HOSTNAME +
                        pkt.Path[2:].split("\\", 1)[1]
                )
        else:
            self.smb_header.MID += 1
            # SMB2
            if SMB2_IOCTL_Request in pkt and pkt.CtlCode == 0x00140204:
                # FSCTL_VALIDATE_NEGOTIATE_INFO
                # This is a security measure asking the server to validate
                # what flags were negotiated during the SMBNegotiate exchange.
                # This packet is ALWAYS signed, and expects a signed response.

                # https://docs.microsoft.com/en-us/archive/blogs/openspecification/smb3-secure-dialect-negotiation
                # > "Down-level servers (pre-Windows 2012) will return
                # > STATUS_NOT_SUPPORTED or STATUS_INVALID_DEVICE_REQUEST
                # > since they do not allow or implement
                # > FSCTL_VALIDATE_NEGOTIATE_INFO.
                # > The client should accept the
                # > response provided it's properly signed".

                # Since we can't sign the response, modern clients will abort
                # the connection after receiving this, despite our best
                # efforts...
                self._response_validate_negotiate_info()
                return
        self.echo(pkt)

    @ATMT.state()
    def SERVING(self):
        """
        Main state when serving files
        """
        pass

    @ATMT.receive_condition(SERVING)
    def receive_tree_connect(self, pkt):
        if SMB2_Tree_Connect_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_tree_connect)
    def send_tree_connect_response(self, pkt):
        self.smb_header.TID = 0x1
        self.smb_header.MID = pkt.MID
        self.send(self.smb_header / SMB2_Tree_Connect_Response(
            ShareType="PIPE",
            ShareFlags="AUTO_CACHING+NO_CACHING",
            Capabilities=0,
            MaximalAccess="+".join(
                ['FILE_LIST_DIRECTORY',
                 'FILE_ADD_FILE',
                 'FILE_ADD_SUBDIRECTORY',
                 'FILE_READ_EA',
                 'FILE_WRITE_EA',
                 'FILE_TRAVERSE',
                 'FILE_DELETE_CHILD',
                 'FILE_READ_ATTRIBUTES',
                 'FILE_WRITE_ATTRIBUTES',
                 'DELETE',
                 'READ_CONTROL',
                 'WRITE_DAC',
                 'WRITE_OWNER',
                 'SYNCHRONIZE',
                 'ACCESS_SYSTEM_SECURITY'])
        ))

    @ATMT.receive_condition(SERVING)
    def receive_ioctl(self, pkt):
        if SMB2_IOCTL_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_ioctl)
    def send_ioctl_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self._response_validate_negotiate_info()

    @ATMT.receive_condition(SERVING)
    def receive_create_file(self, pkt):
        if SMB2_Create_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_create_file)
    def send_create_file_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self.send(
            self.smb_header.copy() / SMB2_Create_Response(
                FileId=SMB2_FILEID(Persistent=0x4000000012,
                                   Volatile=0x4000000001)
            )
        )

    @ATMT.receive_condition(SERVING)
    def receive_query_info(self, pkt):
        if SMB2_Query_Info_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_query_info)
    def send_query_info_response(self, pkt):
        self.smb_header.MID = pkt.MID
        if pkt.InfoType == 0x01:  # SMB2_0_INFO_FILE
            if pkt.FileInfoClass == 0x05:  # FileStandardInformation
                self.send(
                    self.smb_header.copy() / SMB2_Query_Info_Response(
                        Buffer=[('Output',
                                 FileStandardInformation(
                                     AllocationSize=4096,
                                     DeletePending=1))]
                    )
                )

    @ATMT.state()
    def PIPE_WRITTEN(self):
        pass

    @ATMT.receive_condition(SERVING)
    def receive_write_request(self, pkt):
        if SMB2_Write_Request in pkt:
            fi = pkt.FileId
            if fi.Persistent == 0x4000000012 and fi.Volatile == 0x4000000001:
                # The srvsvc file
                raise self.PIPE_WRITTEN().action_parameters(pkt)
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_write_request)
    def send_write_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self.send(
            self.smb_header.copy() / SMB2_Write_Response(
                Count=len(pkt.Data)
            )
        )

    @ATMT.receive_condition(PIPE_WRITTEN)
    def receive_read_request(self, pkt):
        if SMB2_Read_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_read_request)
    def send_read_response(self, pkt):
        self.smb_header.MID = pkt.MID
        # TODO - implement pipe logic
        self.send(
            self.smb_header.copy() / SMB2_Read_Response()
        )

    @ATMT.receive_condition(SERVING)
    def receive_close_request(self, pkt):
        if SMB2_Close_Request in pkt:
            raise self.SERVING().action_parameters(pkt)

    @ATMT.action(receive_close_request)
    def send_close_response(self, pkt):
        self.smb_header.MID = pkt.MID
        self.send(
            self.smb_header.copy() / SMB2_Close_Response()
        )

    @ATMT.state(final=1)
    def END(self):
        self.end()
