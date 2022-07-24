def hex_int(to_parse):
    return int(to_parse, 16)

def _upper_end_hex(string, start):
    for i in range(start, len(string)):
        try:
            int(string[i], 16)
        except ValueError:
            return i


def _switch(a, b):
    tmp = a
    a = b
    b = tmp

    return a, b
