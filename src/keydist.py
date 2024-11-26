"""
Simple SHE key distribution tool

Copyright (C) 2023 Canis Automotive Labs Ltd.

This software is licensed according to the APACHE LICENSE 2.0:

https://www.apache.org/licenses/LICENSE-2.0.txt

Calculate M1, M2 and M3 to set a key, and take M4 and M5 back to verify a key

To use this to demonstrate CryptoCAN, start with two CANPico boards in a factory reset HSM state.

To factory reset an HSM:
------------------------

>>> h = HSM()
>>> h = HSM(secret_key=h.rnd())

To create a key distributor for the target:
-------------------------------------------

>>> h.get_id()
[tuple output]

Then on the host:

>>> from keydist import *
>>> kd1 = KeyDist([paste tuple output here])

[Then copy the code and paste it into the target terminal]
[Verify r matches the expected r]

To create a keypair (global setting):
-------------------------------------

>>> KeyDist.make_keypair()

To program a keypair on a target:
---------------------------------

>>> kd1.program_keypair()
[Paste code for key 1 and then key 2 into the target terminal; verify r each time]
>>> kd1.keypair_programmed()

To create a CryptoCAN session:
------------------------------

On the sender and receiver:

>>> c = CAN()
[can also demonstrate CAN working at this point]

On the sender:

>>> cc = CryptoCAN(transmit=True)

On the receiver:

>>> cc = CryptoCAN(transmit=False)

On the sender:

>>> pf = CANFrame(CANID(0x700), data=b'hello')
>>> frames = cc.create_frames(pf)
>>> frames[0]
>>> frames[1]
>>> c.send_frames(frames)

On the receiver:

>>> frames = c.recv()
[can show the frames]
>>> cc.receive_frame(frames[0])
>>> cc.receive_frame(frames[1])
[outputs nothing the first time, syncing with stream]

On the sender:

>>> c.send_frames(cc.create_frames(pf))

On the receiver:

>>> frames = c.recv()
[can show the frames]
>>> cc.receive_frame(frames[0])
>>> cc.receive_frame(frames[1])
[receives the original frame]

More advanced displaying:
-------------------------

On the receiver:

>>> while True:
...     for f in c.recv():
...         print(f)
...         cc.receive_frame(f)

Then on the transmitter:

>>> from struct import pack
>>> i = 0
>>> while True:
...     pf = CANFrame(CANID(0x700), data=pack('>I', i))
...     c.send_frames(cc.create_frames(pf))
...     i += 1
...     sleep_ms(500)

This creates a series of 4-byte frames, which is still easy to distinguish from the ciphertext
frames.

"""

from binascii import hexlify, unhexlify
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes

class Key:
    def __init__(self, name: str) -> None:
        self.name = name
        self.value = bytes([0] * 16)
        self.counter = 0
        self.write_protect = False
        self.boot_protect = False
        self.debugger_protect = False
        self.key_usage = False
        self.wildcard = False
        self.verify_only = False
        self.empty = True

    def print(self):
        counter = self.counter if self.name.startswith("KEY_") else None

        print(f"{self.name}: {self.value.hex()} counter={counter} flags={flag_str}")

class KeyDist:
    KEY_UPDATE_ENC_C = unhexlify('010153484500800000000000000000b0')
    KEY_UPDATE_MAC_C = unhexlify('010253484500800000000000000000b0')

    SECRET_KEY = 0x0
    ECU_MASTER_KEY = 0x1
    BOOT_MAC_KEY = 0x2
    BOOT_MAC = 0x3
    KEY_1 = 0x4
    KEY_2 = 0x5
    KEY_3 = 0x6
    KEY_4 = 0x7
    KEY_5 = 0x8
    KEY_6 = 0x9
    KEY_7 = 0xa
    KEY_8 = 0xb
    KEY_9 = 0xc
    KEY_10 = 0xd
    RAM_KEY = 0xe

    # These two keys are class variables (i.e. common to all instances)
    k1: bytes = None
    k2: bytes = None

    def __init__(self, get_id: Tuple[bytes, int, bytes]) -> None:
        """
        Create a 'factory reset' HSM and produce the master ECU programming commands.

        get_id is the result of running get_id() on the target board.

        """
        self.uid = get_id[0]
        self.sreg = get_id[1]
        if get_id[2] != bytes([0] * 16):
            raise ValueError("Requires factory-reset target to import")

        self.keys = (
            Key("SECRET_KEY"),
            Key("ECU_MASTER_KEY"),
            Key("BOOT_MAC_KEY"),
            Key("BOOT_MAC"),
            Key("KEY_1"),
            Key("KEY_2"),
            Key("KEY_3"),
            Key("KEY_4"),
            Key("KEY_5"),
            Key("KEY_6"),
            Key("KEY_7"),
            Key("KEY_8"),
            Key("KEY_9"),
            Key("KEY_10"),
            Key("RAM_KEY"))
        
        self.m1: bytes=None
        self.m2: bytes=None
        self.m3: bytes=None
        self.m4: bytes=None
        self.m5: bytes=None
        self.new_key_value: bytes=None
        self.new_key_id: int=None
        self.new_counter_value: int=None
        self.challenge: int=None

        self.factory_program()

    def get_master_ecu_key(self):
        return self.keys[self.ECU_MASTER_KEY].value

    def factory_program(self):
        """
        Generates a random master ECU key, and M1/M2/M3 for setting it.
        Prints output in format for copy/paste to target.
        """
        master_ecu_key_value = get_random_bytes(16)

        print(f"New master ECU key: {master_ecu_key_value.hex()}")

        self.load_key(key_id=self.ECU_MASTER_KEY, 
                      auth_key_id=self.ECU_MASTER_KEY, 
                      new_key=master_ecu_key_value, 
                      new_counter=1)
        print(f"M1={self.m1.hex()}")
        print(f"M2={self.m2.hex()}")
        print(f"M3={self.m3.hex()}")

        print("Run this code on the target to program ECU_MASTER_KEY:")
        print("------")
        print(f"m1 = {self.m1}")
        print(f"m2 = {self.m2}")
        print(f"m3 = {self.m3}")
        print("r = h.load_key(m1, m2, m3)")
        print("------")
        print(f"M4={self.m4.hex()}")
        print(f"M5={self.m5.hex()}")
        print("r should be:")
        print(f"({self.m4}, {self.m5})")

        master_ecu_key = self.keys[self.ECU_MASTER_KEY]
        master_ecu_key.value = master_ecu_key_value
        master_ecu_key.empty = False

    @classmethod
    def make_keypair(cls):
        """
        Generates keypair for CryptoCAN to use
        """
        print("Generating a keypair for communication")
        cls.k1 = get_random_bytes(16)
        cls.k2 = get_random_bytes(16)
        print(f"KEY_1 is {cls.k1.hex()} (used for encryption)")
        print(f"KEY_2 is {cls.k2.hex()} (used for authentication)")

    def program_keypair(self):
        if self.k1 is None or self.k2 is None:
            raise ValueError("Have not generated a keypair yet: use make_keypair()")

        # Keep track of key and counter values
        key_1 = self.keys[self.KEY_1]
        key_2 = self.keys[self.KEY_2]
        
        print(f"Programming KEY_1 to {self.k1.hex()}")
        print(f"Programming KEY_2 to {self.k2.hex()}")

        self.load_key(key_id=self.KEY_1,
                      auth_key_id=self.KEY_1 if key_1.empty else self.ECU_MASTER_KEY, 
                      new_key=self.k1,
                      new_counter=key_1.counter + 1)        
        print(f"M1={self.m1.hex()}")
        print(f"M2={self.m2.hex()}")
        print(f"M3={self.m3.hex()}")

        print("Run this code on the target to program KEY_1:")
        print("------")
        print(f"m1 = {self.m1}")
        print(f"m2 = {self.m2}")
        print(f"m3 = {self.m3}")
        print("r = h.load_key(m1, m2, m3)")
        print("------")
        print(f"M4={self.m4.hex()}")
        print(f"M5={self.m5.hex()}")
        print("r should be:")
        print(f"({self.m4}, {self.m5})")

        self.load_key(key_id=self.KEY_2, 
                      auth_key_id=self.KEY_2 if key_2.empty else self.ECU_MASTER_KEY, 
                      new_key=self.k2,
                      key_usage=True,  # Authentication key
                      new_counter=key_2.counter + 1)
        print("M1={self.m1.hex()}")
        print("M2={self.m2.hex()}")
        print("M3={self.m3.hex()}")

        print("Then run this code on the target to program KEY_2:")
        print("------")
        print(f"m1 = {self.m1}")
        print(f"m2 = {self.m2}")
        print(f"m3 = {self.m3}")
        print("r = h.load_key(m1, m2, m3)")
        print("------")
        print(f"M4={self.m4.hex()}")
        print(f"M5={self.m5.hex()}")
        print("r should be:")
        print(f"({self.m4}, {self.m5})")

        print("Run keypair_programmed() to indicate programming succeeded")

    def keypair_programmed(self):
        """
        Validate that the keypair programmed
        """
        key_1 = self.keys[self.KEY_1]
        key_2 = self.keys[self.KEY_2]

        key_1.value = self.k1
        key_1.counter += 1
        key_1.empty = False

        key_2.value = self.k2
        key_2.counter += 1
        key_2.empty = False
        key_2.key_usage = True  # An authentication key

    def xor3(self, block_a, block_b, block_c):
        return bytes([a ^ b ^ c for a, b, c in zip(block_a, block_b, block_c)])

    def mp(self, out_prev: bytes, x_i: bytes):
        """
        """
        cipher = AES.new(out_prev, AES.MODE_ECB)
        enc = cipher.encrypt(x_i)
        out_next = self.xor3(out_prev, x_i, enc)

        return out_next
                            
    def aes_enc(self, plaintext, key):
        cipher = AES.new(key, AES.MODE_ECB)
        cipher.encrypt(plaintext=plaintext)
        pass  # FIXME

    def kdf(self, k, c):
        out_1 = self.mp(out_prev=bytes([0] * 16), x_i=k)
        k_out = self.mp(out_prev=out_1, x_i=c)
        return k_out
        
    def load_key(self, key_id, auth_key_id, new_key: str, new_counter: int,
                 write_protect=False, boot_protect=False, debugger_protect=False, key_usage=False, wildcard=False, verify_only=False):
        self.new_key_id = key_id
        self.new_key_value = new_key
        self.new_counter_value = new_counter

        k1 = self.kdf(k=self.keys[auth_key_id].value, c=self.KEY_UPDATE_ENC_C)
        k2 = self.kdf(k=self.keys[auth_key_id].value, c=self.KEY_UPDATE_MAC_C)

        m1 = self.uid + bytes([(key_id << 4) | auth_key_id])
        assert(len(m1) == 16)
        block_1 = ((new_counter << 100) | (int(write_protect) << 99) | (int(boot_protect) << 98) | (int(debugger_protect) << 97) | (int(key_usage) << 96) | (int(wildcard) << 95) | (int(verify_only) << 94)).to_bytes(length=16, byteorder='big')
        block_2 = new_key

        cipher = AES.new(key=k1, mode=AES.MODE_CBC, iv=bytes([0] * 16))
        m2 = cipher.encrypt(block_1 + block_2)
        assert(len(m2) == 32)

        hash = CMAC.new(key=k2, ciphermod=AES, msg=m1 + m2)
        m3 = hash.digest()

        k3 = self.kdf(k=new_key, c=self.KEY_UPDATE_ENC_C)
        c_id = ((new_counter << 100) | (1 << 99)).to_bytes(length=16, byteorder='big')

        cipher = AES.new(key=k3, mode=AES.MODE_ECB)
        m4_star = cipher.encrypt(c_id)
        m4 = self.uid + bytes([(key_id << 4) | auth_key_id]) + m4_star
        k4 = self.kdf(k=new_key, c=self.KEY_UPDATE_MAC_C)
        hash = CMAC.new(key=k4, ciphermod=AES, msg=m4)
        m5 = hash.digest()

        self.m1 = m1
        self.m2 = m2
        self.m3 = m3
        self.m4 = m4
        self.m5 = m5

    def challenge_uid(self):
        self.challenge = get_random_bytes(16)
        print(f"challenge = {self.challenge}")
        print("Run this code on the target:")
        print(f"h.get_id({self.challenge})")
        print("Then paste the result into:")
        print("verify_get_id()")

    def verify_get_id(self, get_id_response: Tuple[bytes, int, bytes]):
        self.verify_uid(get_id_response[0], get_id_response[1], get_id_response[2])

    def verify_uid(self, uid: bytes, sreg: int, mac: bytes):
        msg = self.challenge + uid + bytes([sreg])
        hash = CMAC.new(key=self.keys[self.ECU_MASTER_KEY].value, ciphermod=AES, msg=msg)
        if mac == 0:
            # The master key is empty, and this sets the MAC to 0
            # It should have been set in the factory
            print("ECU master key is empty")
            # Record the UID anyway
            self.uid = uid
        elif mac == hash.digest():
            print(f"Challenge verified, UID={uid.hex()}")
            self.uid = uid
        else:
            raise ValueError("Challenge failed to verify")

    def test(self):
        """
        Test vectors
        """

        # Key derivation
        k = unhexlify('000102030405060708090a0b0c0d0e0f')
        c = unhexlify('010153484500800000000000000000b0')
        key = self.kdf(k=k, c=c)
        expected_key = '118a46447a770d87828a69c222e2d17e'
        print(key.hex())
        print(expected_key)
        if key.hex() != expected_key:
            raise ValueError("key != expected_key")

        # CMAC
        key = unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
        msg = unhexlify('6bc1bee22e409f96e93d7e117393172a')
        hash = CMAC.new(key=key, ciphermod=AES, msg=msg)
        d = hash.hexdigest()
        expected_digest = '070a16b46b4d4144f79bdd9dd04a287c'
        print(d)
        print(expected_digest)
        if d != expected_digest:
            raise ValueError("d != expected_digest")

        # Load key
        self.keys[self.ECU_MASTER_KEY].value = unhexlify('000102030405060708090a0b0c0d0e0f')
        key_id = 4
        new_key_hexstr = '0f0e0d0c0b0a09080706050403020100'
        new_key = unhexlify(new_key_hexstr)
        auth_key_id = 1
        new_counter = 1

        self.load_key(key_id=key_id, auth_key_id=auth_key_id, new_key=new_key, new_counter=new_counter)

        print(self.m1.hex())
        print(self.m2.hex())
        print(self.m3.hex())
        print(self.m4.hex())
        print(self.m5.hex())

        expected_m1 = unhexlify('00000000000000000000000000000141')
        expected_m2 = unhexlify('2b111e2d93f486566bcbba1d7f7a9797') + unhexlify('c94643b050fc5d4d7de14cff682203c3')
        expected_m3 = unhexlify('b9d745e5ace7d41860bc63c2b9f5bb46')
        expected_m4 = unhexlify('00000000000000000000000000000141') + unhexlify('b472e8d8727d70d57295e74849a27917')
        expected_m5 = unhexlify('820d8d95dc11b4668878160cb2a4e23e')

        if expected_m1 != self.m1:
            raise ValueError("expected_m1 != m1")
        if expected_m2 != self.m2:
            raise ValueError("expected_m2 != m2")
        if expected_m3 != self.m3:
            raise ValueError("expected_m3 != m3")
        if expected_m4 != self.m4:
            raise ValueError("expected_m4 != m4")
        if expected_m5 != self.m5:
            raise ValueError("expected_m5 != m5")

if __name__ == "__main__":
    get_id = (unhexlify('000000000000000000000000000001'), 0, unhexlify('00000000000000000000000000000000'))
    kd = KeyDist(get_id=get_id)    
    kd.test()
