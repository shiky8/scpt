#!/bin/python_3.9

from base64 import *

class Bases():

    def __init__(self) -> None:
        pass

    def base_encde(self,type: str, masg: str) -> str:
        enc: str = ""
        if (type.lower() == "base64"):
            enc = b64encode(bytes(masg, 'ascii'))
        elif (type.lower() == "base16"):
            enc = str(b16encode(bytes(masg, 'ascii')))
        elif (type.lower() == "base32"):
            enc = str(b32encode(bytes(masg, 'ascii')))
        elif (type.lower() == "base85"):
            enc = str(b85encode(bytes(masg, 'ascii')))
        return enc

    def base_dencde(self,type: str, hash: str) -> str:
        dec: str = ""
        if (type.lower() == "base64"):
            dec = str(b64decode(hash))
        elif (type.lower() == "base16"):
            dec = str(b16decode(hash))
        elif (type.lower() == "base32"):
            dec = str(b32decode(hash))
        elif (type.lower() == "base85"):
            dec = str(b85decode(hash))
        return dec

if __name__=="__main__":
    ED: str = str(input("Enter , en for encoding  or de  for decoding: "))
    Bt: str = str(input("Enter the base type: "))
    CP: str = str(input("Enter the masg or the hash: "))
    BS = Bases()
    if (ED=="en"):
        BOutput: str = BS.base_encde(Bt,CP)
        print(BOutput)
    else:
        BOutput = BS.base_dencde(Bt,CP)
        print(BOutput)
