import socket

from honey_smb.netbios.name_server.constants import opcodes, nm_bits, replycodes

QUERYREC = 0x1000  # Query Record
ANSREC = 0x0100  # Answer Record
NSREC = 0x0010  # NS Rec (never used)
ADDREC = 0x0001  # Additional Record


class NameServicePacketHeader:
    def __init__(self, name_transaction_id, flags, qd_count, an_count, ns_count, ar_count):
        self.name_transaction_id = name_transaction_id  # unsigned short int
        self.flags = flags
        self.qd_count = qd_count  # unsigned short int
        self.an_count = an_count  # unsigned short int
        self.ns_count = ns_count  # unsigned short int
        self.ar_count = ar_count  # unsigned short int
        self.header = []
        self.put_name_service_transaction_id(self.header, self.name_transaction_id)
        self.put_name_service_header_flags(self.header, self.flags)

    def put_name_service_transaction_id(self, header, transaction_id):
        transaction_id_bytes = transaction_id.to_bytes(2, 'big')
        header.insert(0, transaction_id_bytes[0])
        header.insert(1, transaction_id_bytes[1])
        return header

    def put_name_service_header_flags(self, header, flags):
        flag_bytes = flags.concat_flags().to_bytes(2, 'big')
        header.insert(2, flag_bytes[0])
        header.insert(3, flag_bytes[1])
        return header

    def put_name_service_header_record_counts(self, header, record_count):
        network_order_one = 1
        header.insert(4, 0)
        header.insert(5, (network_order_one if QUERYREC & record_count else 0))
        header.insert(6, 0)
        header.insert(7, (network_order_one if ANSREC & record_count else 0))
        header.insert(8, 0)
        header.insert(9, (network_order_one if NSREC & record_count else 0))
        header.insert(10, 0)
        header.insert(11, (network_order_one if ADDREC & record_count else 0))

    def __str__(self):
        transaction_id = "0x" + str(hex(self.name_transaction_id.to_bytes(2, 'little')[1]))[2:].zfill(2) + str(
            hex(self.name_transaction_id.to_bytes(2, 'little')[0]))[2:].zfill(2)
        response_status = self.flags.get_r_bit_friendly_name()
        op_code = self.flags.get_op_code_friendly_name()
        flags = self.flags.get_nm_flags_friendly_name()
        reply_code = self.flags.get_reply_code_friendly_name()
        return transaction_id + '\n' + response_status + '\n' + op_code + '\n' + flags + '\n' + reply_code + '\n'


def demangle_flags(flags):
    bit_string = ""
    for b in flags:
        print(bin(socket.ntohs(b))[2:].zfill(8))
        print(hex(socket.ntohs(b)))
        bit_string = bit_string + bin(socket.ntohs(b))[2:].zfill(8)
    print(bit_string)
    return int(bit_string[0:1], 2), int(bit_string[1:5], 2), int(bit_string[5:11], 2), int(bit_string[11:15])


class NameServicePacketHeaderFlags:
    def __init__(self, r, op_code, nm_flags, r_code):
        self.r = r
        self.op_code = op_code
        self.nm_flags = nm_flags
        self.r_code = r_code

    def concat_flags(self):
        r_bit = bin(self.r & 1)[2:].zfill(1)
        op_code_bits = bin(self.op_code & 0xF)[2:].zfill(4)
        flag_bits = bin(self.nm_flags & 0x7F)[2:].zfill(7)
        r_code_bits = bin(self.r_code & 0xF)[2:].zfill(4)
        return int(r_bit + op_code_bits + flag_bits + r_code_bits, 2)

    def get_r_bit_friendly_name(self):
        match self.r:
            case 0:
                return "Message is not a response."
            case 1:
                return "Message is a response."
            case default:
                return "Response bit not set."

    def get_op_code_friendly_name(self):
        match self.op_code:
            case opcodes.OPCODE_QUERY:
                return "Query"
            case opcodes.OPCODE_REGISTER:
                return "Registration"
            case opcodes.OPCODE_RELEASE:
                return "Registration release"
            case opcodes.OPCODE_WACK:
                return "WACK"
            case opcodes.OPCODE_REFRESH:
                return "Refresh"
            case opcodes.OPCODE_ALTREFRESH:
                return "Alt Refresh"
            case opcodes.OPCODE_MULTIHOMED:
                return "Multi-homed"
            case default:
                return "Unknown opcode"

    def get_nm_flags_friendly_name(self):
        authoritive_answer = "Server is an authority for the domain." if self.nm_flags & nm_bits.NM_AA_BIT else "Server is not an authority for the domain."
        truncated_answer = "Message is truncated." if self.nm_flags & nm_bits.NM_TR_BIT else "Message is not truncated."
        recursion_desired = "Recursion desired." if self.nm_flags & nm_bits.NM_RD_BIT else "Recursion not desired."
        recursion_available = "Recursion available." if self.nm_flags & nm_bits.NM_RA_BIT else "Recursion not available."
        broadcast = "Broadcast packet." if self.nm_flags & nm_bits.NM_B_BIT else "Not a broadcast packet."
        return authoritive_answer + '\n' + truncated_answer + '\n' + recursion_desired + '\n' + recursion_available + '\n' + broadcast

    def get_reply_code_friendly_name(self):
        match self.r_code:
            case replycodes.RCODE_POS_RSP:
                return "Positive Response."
            case replycodes.RCODE_FMT_ERR:
                return "Format Error."
            case replycodes.RCODE_SRV_ERR:
                return "Server Failure."
            case replycodes.RCODE_NAM_ERR:
                return "Name Not Found."
            case replycodes.RCODE_IMP_ERR:
                return "Unsupported Request."
            case replycodes.RCODE_RFS_ERR:
                return "Refused."
            case replycodes.RCODE_ACT_ERR:
                return "Active Error."
            case replycodes.RCODE_CFT_ERR:
                return "Name In Conflict."
            case default:
                return "Unknown reply code."
