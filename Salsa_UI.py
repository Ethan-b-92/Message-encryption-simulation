import base64
import random

from Salsa import Salsa
from Msg import Msg


def encrypte1(msg, eg_mutual_key, iv):
    salsa = Salsa_UI(eg_mutual_key, iv)
    c_msg, nonce_list = salsa.encrypte2(msg)
    return c_msg, nonce_list


def decrypte1(c_msg, dh_mutual_key, iv, nonce_list):
    salsa = Salsa_UI(dh_mutual_key, iv)
    msg = salsa.decrepte2(c_msg, nonce_list)
    return msg.rstrip()


class Salsa_UI:
    def __init__(self, key, iv):
        assert key != 0
        self._s20 = Salsa()
        self._key = key
        self._iv = iv

        assert len(self._key) < 33

        while len(self._key) < 32:
            self._key.append(0)

    def encrypte2(self, string):
        msg = Msg(string)
        hmsg = msg.to_hex()
        #generate nonces
        nonce_list = []
        for i in range(0,len(hmsg) // 16):
            list = []
            for j in range(8):
                list.append(random.getrandbits(64))
            nonce_list.append(list)
        return self._calc_encrypte_by_hex_list(hmsg, nonce_list)

    #encryption with salsa20 using cbc mode
    def _calc_encrypte_by_hex_list(self, hmsg, nonce_list):
        num_word = 16

        cypher_hash_text_list = []
        #xor iv vector with the first block of data
        hmsg[0] = hmsg[0] ^ self._iv
        for i in range(0, len(hmsg) // num_word):
            block_counter = [int(x) for x in hex(i)[2:]]
            if len(block_counter) < 8:
                block_counter.extend((8 - len(block_counter)) * [0])
            self._s20(self._key, nonce_list[i], block_counter[0:8])  # clac internal enc matrix
            ctext_list = self._s20.encrypt(hmsg[i * num_word:(i + 1) * num_word])  # use the calc matrix to enc
            cypher_hash_text_list.extend(ctext_list)
            #xor the 'i' block of ctext with the 'i+1' block of ptext
            if i<len(hmsg) // num_word:
                hmsg[i+1] = cypher_hash_text_list[i] ^ hmsg[i+1]

        return cypher_hash_text_list, nonce_list

    def decrepte2(self, chextxt, nonce_list):
        """ chextxt is list of hex value similar to result of Msg.to_hex() """
        list_num, nonce_list = self._calc_encrypte_by_hex_list(chextxt, nonce_list)
        return Msg.hex_list_to_string(list_num)

