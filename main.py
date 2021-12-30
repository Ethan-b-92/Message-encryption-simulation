import hashlib

import elgamal
import rabin as Rabin
import random
import Salsa_UI


def main():
    #the key should be randomly generated. a constant string is used to show that el-gamal sends the key properly
    encryption_key = "32bitkey32bitkey32bitkey32bitkey"
    print("Alice generates a key to use in salsa20 encryption, the key is: " + encryption_key)
    print("Alice generates private and public keys in order to encrypt the key using el-gamal encryption.\n")
    keys = elgamal.gen_key(256, 32)
    priv = keys['privateKey']
    pub = keys['publicKey']
    encrypted_key = elgamal.encrypt(pub, encryption_key)
    print("Alice encrypted the key successfully using El-Gamal cipher and sends it to bob, the key is: ")
    print(encrypted_key)
    print("Bob received the encrypted key\n")
    dec = elgamal.decrypt(priv, encrypted_key)
    print("Bob decrypted key using El-GAMAL cipher, the key is:" + str(dec))
    
    
    input_str = 'Hello Bob, how are you?'
    print("Alice sends a mail to bob with message:\n" + input_str)
    print("Alice starts encrypting the message using encryption key. \n")
    #generate a random 512 bit initialization vector for cbc mode
    iv = random.getrandbits(512)
    # encryption
    encoded_string = encryption_key.encode()
    byte_array_key = bytearray(encoded_string)
    ctext, nonce_list = Salsa_UI.encrypte1(input_str, byte_array_key, iv)
    print("The message was encrypted successfully!")
    
    
    p_alice, q_alice, n_alice = Rabin.generate_keys_for_rabin()
    print("Alice generates keys for rabin signature: p = " + str(p_alice) + ", q = " + str(q_alice) + " n = " + str(n_alice))
    alice_hashed_message = hashlib.sha224(input_str.encode('utf-8')).hexdigest()
    sig_alice, pad_num = Rabin.sing_msg(alice_hashed_message,p_alice,q_alice)
    print("Alice has successfully signed the message, and she sends Bob the signature and the ctext.")
    
    
    print("Bob has received the message and starts decrypting it.")
    # decryption
    decrypt_output = Salsa_UI.decrypte1(ctext, byte_array_key, iv, nonce_list)
    
    
    bob_hashed_message = hashlib.sha224(decrypt_output.encode('utf-8')).hexdigest()
    assert Rabin.verify(bob_hashed_message, sig_alice, pad_num, n_alice) is True
    print("The message was verified using rabin signature")
    print("Bob has successfully decrypted the message! the message is: ")
    print(decrypt_output)

if __name__ == "__main__":
    main()
