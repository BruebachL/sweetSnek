import struct

from honey_smb.HoneySMB2.libs.structure import Structure

# RPC Packet Type Constants
RPC_REQUEST = 0
RPC_RESPONSE = 2
RPC_BIND_REQUEST = 11
RPC_BIND_ACK = 12

# Transfer Syntax and Version Strings
NDR_TRANSFER_SYNTAX_VERSION_2 = "045d888aeb1cc9119fe808002b10486002000000"


# Structs don't allow variable length strings in their definition, so we have to shove it into a struct inline with
# this format string hack.
def pack_variable_length_string(string_to_pack):
    return struct.pack('<H', len(string_to_pack) + 1) + struct.pack(
        '<%ds' % (len(string_to_pack)), str(string_to_pack)) + struct.pack('<BB', 0, 0)


def pack_name_structure(name_to_pack, structure_to_pack=None):
    if structure_to_pack is None:
        structure_to_pack = NetShareNameStructure()
    encoded_name = b''
    for char in name_to_pack:
        encoded_name = encoded_name + struct.pack('<H', ord(char))
    # This is the C-Style Null terminator
    encoded_name = encoded_name + struct.pack('<H', 0)
    # Since the pointers increase by the Byte length % 2 (ActualCount), we have to pad here.
    while len(encoded_name) % 4 != 0:
        encoded_name = encoded_name + struct.pack('<H', 0)
    structure_to_pack['Data'] = encoded_name
    structure_to_pack['MaxCount'] = len(name_to_pack) + 1
    structure_to_pack['Offset'] = 0
    structure_to_pack['ActualCount'] = len(name_to_pack) + 1
    return structure_to_pack


def unpack_name_structure_with_pointer(buffer):
    structure_to_pack = ServiceManagerNameStructure()
    print(str(buffer[0:4]))
    structure_to_pack['Pointer'] = struct.unpack('<I', str(buffer[0:4]))[0]
    print("Pointer")
    print(structure_to_pack['Pointer'])
    structure_to_pack['MaxCount'] = struct.unpack('<I', str(buffer[4:8]))[0]
    print("MaxCount")
    print(structure_to_pack['MaxCount'])
    structure_to_pack['Offset'] = struct.unpack('<I', str(buffer[8:12]))[0]
    print("Offset")
    print(structure_to_pack['Offset'])
    structure_to_pack['ActualCount'] = struct.unpack('<I', str(buffer[12:16]))[0]
    print("ActualCount")
    print(structure_to_pack['ActualCount'])
    print(type(structure_to_pack['MaxCount']))
    print("asdf")
    print(structure_to_pack['ActualCount'] * 2)
    structure_to_pack['Data'] = struct.unpack('%ds' % (structure_to_pack['ActualCount'] * 2),
                                              str(buffer[16:16 + structure_to_pack['ActualCount'] * 2]))
    print("BUFFER RETURNING")
    print(buffer[16 + structure_to_pack['ActualCount'] * 2:])
    return structure_to_pack, buffer[16 + structure_to_pack['ActualCount'] * 2:]


def unpack_name_structure(buffer):
    structure_to_pack = NetShareNameStructure()
    print(str(buffer[0:4]))
    structure_to_pack['MaxCount'] = struct.unpack('<I', str(buffer[0:4]))[0]
    print("MaxCount")
    print(structure_to_pack['MaxCount'])
    structure_to_pack['Offset'] = struct.unpack('<I', str(buffer[4:8]))[0]
    print("Offset")
    print(structure_to_pack['Offset'])
    structure_to_pack['ActualCount'] = struct.unpack('<I', str(buffer[8:12]))[0]
    print("ActualCount")
    print(structure_to_pack['ActualCount'])
    print(type(structure_to_pack['MaxCount']))
    structure_to_pack['Data'] = struct.unpack('%ds' % (structure_to_pack['ActualCount'] * 2),
                                              str(buffer[12:12 + structure_to_pack['ActualCount'] * 2]))
    print("BUFFER RETURNING")
    print(buffer[12 + structure_to_pack['ActualCount'] * 2:])
    return structure_to_pack, buffer[12 + structure_to_pack['ActualCount'] * 2:]


# 16 Bytes common header

class RPCCommonHeader(Structure):
    structure = (
        ('Version', 'B=0'),
        ('MinorVersion', '<B=0'),
        ('PacketType', '<B=0'),
        ('PacketFlags', '<B=0'),
        ('DataRepresentation', '<I=0'),
        ('FragLength', '<H=0'),
        ('AuthLength', '<H=0'),
        ('CallID', '<I=0'),
        ('Data', ':=""'),
    )


def copy_common_header_fields(common_header, return_header):
    return_header['Version'] = common_header['Version']
    return_header['MinorVersion'] = common_header['MinorVersion']
    return_header['DataRepresentation'] = common_header['DataRepresentation']
    return_header['CallID'] = common_header['CallID']
    return return_header


# 8 Bytes length header
class RPCBindHeader(Structure):
    structure = (
        ('MaxXmitFrag', '<H=0'),
        ('MaxRecvFrag', '<H=0'),
        ('AssocGroup', '<I=0'),
        ('Data', ':=""'),
    )


def copy_bind_header_fields(bind_header, return_header):
    return_header['MaxXmitFrag'] = bind_header['MaxXmitFrag']
    return_header['MaxRecvFrag'] = bind_header['MaxRecvFrag']
    if bind_header['AssocGroup'] == 0:
        return_header['AssocGroup'] = 0x123456789  # Doesn't seem to matter. Copy Samba for now.
    else:
        return_header['AssocGroup'] = bind_header[
            'AssocGroup']  # Client has an association group, just believe him.
    return return_header


# 48 Bytes length header
class RPCBindCtxHeader(Structure):
    structure = (
        ('NumCtxItems', '<I=0'),
        ('CtxItems', '44s=""'),  # TODO: Subdivide this into valid CtxItems (structs)
        ('Data', ':=""'),
    )


class RPCBindCtxItem(Structure):
    structure = (
        ('ContextID', '<H=0'),
        ('NumTransItems', '<H=0'),
        ('Interface', '<IIII=0'),
        ('InterfaceVersion', '<H=0'),
        ('InterfaceVersionMinor', '<H=0'),
        ('TransferSyntax', '<IHHH6s'),
        ('TransferSyntaxVersion', '<I')
    )


class RPCBindTransferSyntax(Structure):
    structure = (
        ('TransferSyntax', '<16s'),
        ('TransferSyntaxVersion', '<4s'),
    )


class RPCBindAckResultsHeader(Structure):
    structure = (
        ('NumResults', '<I'),
        ('Data', ':=""'),
    )


class RPCBindAckResult(Structure):
    structure = (
        ('AckResult', '<I'),
    )


class NetShareEnumAllRequest(Structure):
    structure = (
        ('alloc_hint', '<I=0'),
        ('context_id', '<H=0'),
        ('opnum', '<H=0'),
        ('server_unc_referent_id', '<I'),
        ('max_count', '<I'),
        ('offset', '<I'),
        ('actual_count', '<I'),
        ('Data', ':=""'),
    )


class NetShareEnumAllRequestRest(Structure):
    structure = (
        ('level', '<I=0'),
        ('ctr', '<I=0'),
        ('ctr_referent_id', '<I'),
        ('count', '<I'),
        ('net_share_info1', '<I'),
        ('max_buffer', '<I'),
        ('Data', ':=""'),
    )


class NetShareEnumAllResponse(Structure):
    structure = (
        ('alloc_hint', '<I=0'),
        ('context_id', '<H=0'),
        ('cancel_count', '<H=0'),
        ('level', '<I=0'),
        ('Data', ':=""'),
    )


class IntegerValuePointer(Structure):
    structure = (
        ('Pointer', '<I=0'),
        ('Value', '<I=0'),
    )


class NetShareNameStructure(Structure):
    structure = (
        ('MaxCount', '<I=0'),
        ('Offset', '<I=0'),
        ('ActualCount', '<I=0'),
        ('Data', ':=""'),
    )


class ServiceManagerHeader(Structure):
    structure = (
        ('alloc_hint', '<I=0'),
        ('context_id', '<H=0'),
        ('opnum', '<H=0'),
        ('Data', ':=""'),
    )


class ServiceManagerNameStructure(Structure):
    structure = (
        ('Pointer', '<I=0'),
        ('MaxCount', '<I=0'),
        ('Offset', '<I=0'),
        ('ActualCount', '<I=0'),
        ('Data', ':=""'),
    )


class NetShareShareInfoPointerStructure(Structure):
    structure = (
        ('Name', '<I=0'),
        ('Type', '<I=0'),
        ('Comment', '<I=0'),
    )


class RPCPolicyHandle(Structure):
    structure = (
        ('policy_handle', '20s'),
        ('Data', ':=""')
    )


class RPCWindowsError(Structure):
    structure = (
        ('windows_error', '<I=0'),
        ('Data', ':=""'),
    )
