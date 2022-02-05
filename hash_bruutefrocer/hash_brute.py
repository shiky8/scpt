#!/bin/python_3.9

from typing import List,Union,Optional,Dict,Set
import hashlib,os
try:
    from cryptography_me_she import bases
except:
    pass

class Hash_Brut():

    def __init__(self) -> None:
        pass

    def hashdecod(self,type_hash: str, hash: str) -> str:
        dir: str = str(os.getcwd().replace("cryptography_me_she", ""))
        try:
            if "nt" in os.name:
                 wordList = open(dir + "hash_bruutefrocer\\word.list", 'r').readlines()
            else:
                wordList = open(dir + "hash_bruutefrocer/word.list", 'r').readlines()
        except:
            wordList = open(dir + "/word.list", 'r').readlines()
        hash2: str = ""
        plantext: str = ""
        for hashs in wordList:
            hashs = hashs.split()
            hashs = bytes(str(hashs).replace("[", "").replace("]", "").replace("'", ""), "ascii")
            if (type_hash.lower() == "md5"):
                hash2 = hashlib.md5(hashs).hexdigest()
            elif (type_hash.lower() == "sha1"):
                hash2 = hashlib.sha1(hashs).hexdigest()
            elif (type_hash.lower() == "sha256"):
                hash2 = hashlib.sha256(hashs).hexdigest()
            elif (type_hash.lower() == "sha3_224"):
                hash2 = hashlib.sha3_224(hashs).hexdigest()
            elif (type_hash.lower() == "sha224"):
                hash2 = hashlib.sha224(hashs).hexdigest()
            elif (type_hash.lower() == "sha512"):
                hash2 = hashlib.sha512(hashs).hexdigest()
            elif ("base" in type_hash.lower()):
                hash2 = bases.base_dencde(type_hash, hash)
            if (hash == hash2):
                plantext = str(hashs)
                break
        return plantext.replace("b", '').replace("'", '')

if __name__ == "__main__":
    HBrut = Hash_Brut()
    hash: str = "f1e719e97deac6f4bf9f6ea82a7b0c66"
    types: str = "md5"
    HB_Output: str = HBrut.hashdecod(types,hash)
    print(HB_Output)
