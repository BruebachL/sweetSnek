import socket
import time

from smb.netbios.name_server.name_service_packet_header import NameServicePacketHeaderFlags, NameServicePacketHeader, \
    QUERYREC, ADDREC, demangle_flags

WORKSTATION_SERVICE = 0x00
MESSENGER_SERVICE = 0x03
FILE_SERVER_SERVICE = 0x20
DOMAIN_MASTER_BROWSER = 0x1B


def encode_name(name, type, scope):
    output = bytearray()
    name = name.upper()
    name = first_level_encode(name, type)
    append_length_and_string(output, name)
    if isinstance(scope, str):
        scope = scope.upper()
        append_length_and_string(output, scope)
    else:
        for sub_scope in scope:
            append_length_and_string(output, sub_scope.upper())
    append_length_and_string(output, '')
    return output


def first_level_encode(name, name_type):
    output = ""
    if name[0] == '*':
        name = '*' + 15 * '\x00'
    else:
        if len(name) >= 15:
            name = name[:15] + chr(name_type)
        else:
            name = name + ' ' * (15 - len(name)) + chr(name_type)
    name = bytes(name, "UTF-8").hex()
    for byte in name:
        output = output + str(chr(int(byte, 16) + ord('A')))
    return output


def first_level_decode(name):
    output = ""
    buffer_byte = None
    for byte in name:
        if buffer_byte is not None:
            actual_byte = hex(ord(buffer_byte) - ord('A'))[2:] + hex(ord(byte) - ord('A'))[2:]
            output = output + chr(int(actual_byte, 16))
            buffer_byte = None
        else:
            buffer_byte = byte
    return output


def decode_name(name):
    output = []
    position = 0
    while position != len(name):
        length = int(name[position + 2:position + 4], 16)
        position = position + 4
        output.append(name[position:position + length])
        position = position + length
    output[0] = first_level_decode(output[0])
    return '.'.join(output)


def append_length_and_string(to_append_to, to_append):
    length = len(to_append)
    to_append_to.append(length)
    for character in to_append:
        to_append_to.append(ord(character))
    return


if __name__ == "__main__":
    # print(encode_name("Neko  ", WORKSTATION_SERVICE, ["CAT", "ORG"]))
    # print((decode_name(encode_name("Neko  ", WORKSTATION_SERVICE, ["CAT", "ORG"]))))
    # print(encode_name("Neko  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", DOMAIN_MASTER_BROWSER, ["CAT", "ORG"]))
    # print(encode_name("*asdf", FILE_SERVER_SERVICE, ["CAT", "ORG"]))
    # print(decode_name(encode_name("Neko  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", MESSENGER_SERVICE, ["CAT", "ORG"])))
    name_service_question_flags = NameServicePacketHeaderFlags(0, 0x0, int('000100010000', 2), 0)
    name_service_question = NameServicePacketHeader(1337, name_service_question_flags, 1, 0, 0, 0)
    name_service_question.put_name_service_header_record_counts(name_service_question.header, QUERYREC)
    output = b''
    for entry in name_service_question.header:
        output = output + entry.to_bytes(1, 'big')
    encoded_name = encode_name("HONEYPOT-F1337", WORKSTATION_SERVICE, [])
    output = output + encoded_name
    output = output + 0x0020.to_bytes(2, 'big')
    output = output + 0x0001.to_bytes(2, 'big')
    print(name_service_question)
    host = "192.168.1.255"
    port = 137
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    receive_socket.bind(("", 137))
    sock.sendto(output, (host, port))
    print("Waiting for answer...")
    answer = receive_socket.recv(2048)
    print(answer[0:2])
    for b in answer:
        print(hex(b))
    answer_header_flag_bits = answer[2:4]
    print()
    answer_r_bit, answer_op_code_bits, answer_flag_bits, answer_r_code_bits = demangle_flags(answer_header_flag_bits)
    answer_header_flags = NameServicePacketHeaderFlags(answer_r_bit, answer_op_code_bits, answer_flag_bits, answer_r_code_bits)
    answer_header = NameServicePacketHeader(answer[0] + answer[1], answer_header_flags, answer[4] + answer[5], answer[6] + answer[7], answer[8] + answer[9], answer[10] + answer[11])
    print(answer_header)
    print(answer[0:12])
    print("Waiting for answer...")
    time.sleep(1)
