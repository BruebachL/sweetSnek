from honey_smb.HoneySMB2.libs.structure import Structure


# 24 Bytes length header
class RPCPacket(Structure):
    structure = (
        ('Version', 'B=0'),
        ('MinorVersion', '<B=0'),
        ('PacketType', '<B=0'),
        ('PacketFlags', '<B=0'),
        ('DataRepresentation', '<I=0'),
        ('FragLength', '<H=0'),
        ('AuthLength', '<H=0'),
        ('CallID', '<I=0'),
        ('MaxXmitFrag', '<H=0'),
        ('MaxRecvFrag', '<H=0'),
        ('AssocGroup', '<I=0'),
    )

class RPCBindPacket(Structure):
    structure = (
        ('NumCtxItems', '<I=0'),
        ('CtxItems', '44s=""')
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
        ('SecondaryAddressLength', ),
        ('SecondaryAddress', ),
        ('NumResults', ),
        ('CtxItems', )
    )

class RPCBindAckCtxItem(Structure):
    structure = (
        ('AckResult', ),
        ('TransferSyntax', ),
        ('TransferSyntaxVersion', )
    )

class RPCBindAckFullPacket(Structure):
    structure = (
        ('rpc_vers', 'B=0'),
        ('rpc_vers_minor', '<B=0'),
        ('PTYPE', '<B=0'),
        ('pfc_flags', '<B=0'),
        ('packed_drep', '<I=0'),
        ('frag_length', '<H=0'),
        ('auth_length', '<H=0'),
        ('call_id', '<I=0'),
        ('max_xmit_frag', '<H=0'),
        ('max_recv_frag', '<H=0'),
        ('assoc_group_id', '<I=0'),
    )

class NetShareEnumAllRequest(Structure):
    structure = (
        ('rpc_vers', 'B=0'),
        ('rpc_vers_minor', '<B=0'),
        ('PTYPE', '<B=0'),
        ('pfc_flags', '<B=0'),
        ('packed_drep', '<I=0'),
        ('frag_length', '<H=0'),
        ('auth_length', '<H=0'),
        ('call_id', '<I=0'),
        ('alloc_hint', '<I=0'),
        ('context_id', '<H=0'),
        ('opnum', '<H=0'),
        ('server_unc_referent_id', '<I'),
        ('max_count', '<I'),
        ('offset', '<I'),
        ('actual_count', '<I')
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
        ('rpc_vers', 'B=0'),
        ('rpc_vers_minor', '<B=0'),
        ('PTYPE', '<B=0'),
        ('pfc_flags', '<B=0'),
        ('packed_drep', '<I=0'),
        ('frag_length', '<H=0'),
        ('auth_length', '<H=0'),
        ('call_id', '<I=0'),
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
