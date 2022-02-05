#!/bin/python_3.9

class HASH_Name():

    def __init__(self) -> None:
        global hashName
        global HS_LEN

    def hahs_type(self,hash:str) -> str:
        self.hashName: str = "the hash name maybe: \n"
        self.HS_LEN: int = len(hash)
        if (self.HS_LEN == 32):
            self.hashName += "md-5,\n"
            self.hashName += "md-4, \n"
            self.hashName += "MD6-128, \n"
            self.hashName += "NTLM, \n"
            self.hashName += "MD2 \n"

        elif (self.HS_LEN == 40):
            self.hashName += "sha1, \n"
            self.hashName += "RIPEMD-160 \n"

        elif (self.HS_LEN == 56):
            self.hashName += "sha224, \n"
            self.hashName += "SHA2-512/224, \n"
            self.hashName += "BLAKE-224 \n"

        elif (self.HS_LEN == 64):
            self.hashName += "sha-256, \n"
            self.hashName += "MD6-256, \n"
            self.hashName += "SHAKE-128, \n"
            self.hashName += "BLAKE-256 \n"

        elif (self.HS_LEN == 96):

            self.hashName += "sha384, \n"
            self.hashName += "SHA2-512/256, \n"
            self.hashName += "BLAKE-384 \n"

        elif (self.HS_LEN == 128):
            self.hashName += "sha512, \n"
            self.hashName += "MD6-512, \n"
            self.hashName += "SHAKE-256, \n"
            self.hashName += "Whirlpool, \n"
            self.hashName += "GOST, \n"
            self.hashName += "BLAKE-512 \n"

        elif (self.HS_LEN == 48):
            self.hashName += "Tiger \n"
        elif (self.HS_LEN >= 32 and len(hash) <= 64):
            self.hashName += "Snefru \n"

        elif (self.HS_LEN == 4):
            self.hashName += "CRC-16 \n"

        elif (self.HS_LEN == 8):
            self.hashName += "CRC-32 \n"
        else:
            self.hashName = "can't find the hash type "
        return self.hashName

if __name__ == "__main__":
    hash: str = "cefd573c75ef3e8eee5ae1ffe4243497"
    # hash="716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a"
    # hash="c6cbd89c926ab525c242e6621f2f5fa73aa4afe3d9e24aed727faaadd6af38b620bdb623dd2b4788b1c8086984af8706"
    print("hash: ",hash,"\nHash_len: ",len(hash))
    HN = HASH_Name()
    Houtput: str = HN.hahs_type(hash)
    print(Houtput)

