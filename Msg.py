import re
from functools import reduce


class Msg:
    def __init__(self, msg):
        block_size = 64
        if len(msg) % block_size != 0:
            msg += " " * (block_size - len(msg) % block_size)
        self.msg_list = re.findall(".{4}", msg)

    def to_hex(self):
        hex_string_list = ["".join("{:02x}".format(ord(c)) for c in text) for text in self.msg_list]
        hex_list = [int(text, 16) for text in hex_string_list]
        return hex_list

    def hex_list_to_string(hex_list):
        # only plaintext because their are hex code which dont have ascii
        string_list = []
        for hexa in hex_list:
            string_list.append(bytes.fromhex(hex(hexa)[2:]).decode("windows-1252"))
        return Msg.string_list_to_string(string_list)

    def to_string(self):
        return Msg.string_list_to_string(self.msg_list)

    def string_list_to_string(string_list):
        f = lambda s1, s2: s1 + s2
        return reduce(f, string_list, "")