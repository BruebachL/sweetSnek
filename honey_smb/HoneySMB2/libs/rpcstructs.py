from honey_smb.HoneySMB2.libs.structure import Structure


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


class RPCBindAckPacket(Structure):
    structure = (
        ('SecondaryAddressLength',),
        ('SecondaryAddress',),
        ('NumResults',),
        ('CtxItems',)
    )


class RPCBindAckCtxItem(Structure):
    structure = (
        ('AckResult',),
        ('TransferSyntax',),
        ('TransferSyntaxVersion',)
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
        ('resume_handle_referent_id', '<I'),
        ('resume_handle', '<I')
    )


class NetShareEnumAllResponse(Structure):
    structure = (
        ('alloc_hint', '<I=0'),
        ('context_id', '<H=0'),
        ('cancel_count', '<H=0'),
        ('level', '<I=0'),
        ('net_share_ctr', '<I=0'),
        ('net_share_referent_id', '<I=0'),
        ('count', '<I=0'),
        ('net_share_info_referent_id', '<I=0'),
        ('max_count', '<I=0'),
        ('net_share_name_referent_id', '<I=0'),
        ('net_share_type', '<I=0'),
        ('comment_referent_id', '<I=0'),
        ('name_max_count', '<I=0'),
        ('name_offset', '<I=0'),
        ('name_actual_count', '<I=0'),
        ('name', '<12s'),
        ('comment_max_count', '<I=0'),
        ('comment_offset', '<I=0'),
        ('comment_actual_count', '<I=0'),
        ('comment', '<24s'),
        ('total_entries', '<I=0'),
        ('resume_handle_referent_id', '<I=0'),
        ('resume_handle', '<I=0'),
        ('windows_error', '<I=0'),

    )
