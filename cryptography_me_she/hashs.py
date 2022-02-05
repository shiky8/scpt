#!/bin/python_3.9

import hashlib,os
try:
    from cryptography_me_she import bases
except:
    import bases


class Hashing():

    def __init__(self) -> None:
        pass

    def hashing(self, type_hash: str, masg: str) -> str:
        masg: bytes = bytes(masg, "ascii")
        hash2: str = ""
        if (type_hash.lower() == "md5"):
            hash2 = str(hashlib.md5(masg).hexdigest())
        elif (type_hash.lower() == "sha1"):
            hash2 = str(hashlib.sha1(masg).hexdigest())
        elif (type_hash.lower() == "sha256"):
            hash2 = str(hashlib.sha256(masg).hexdigest())
        elif (type_hash.lower() == "sha3_224"):
            hash2 = str(hashlib.sha3_224(masg).hexdigest())
        elif (type_hash.lower() == "sha224"):
            hash2 = str(hashlib.sha224(masg).hexdigest())
        elif (type_hash.lower() == "sha512"):
            hash2 = str(hashlib.sha512(masg).hexdigest())
        elif ("base" in type_hash.lower()):
            hash2 = str(bases.base_encde(type_hash, masg))
        dir: str = str(os.getcwd().replace("cryptography_me_she", ""))
        try:
            if "nt" in os.name:
                word = open(dir + "hash_bruutefrocer\\word.list", "a")
                word.write('\n' + str(masg)[1:].replace("'", ""))
                word.close()
            else:
                 word = open(dir + "hash_bruutefrocer/word.list", "a")
                 word.write('\n' + str(masg)[1:].replace("'", ""))
                 word.close()
        except:
            print("no word list")
        return hash2

if __name__=="__main__":
    type_hash: str = str(input("hash_type: "))
    masg: str = str(input("enter masg"))
    HA = Hashing()
    hash: str = HA.hashing(type_hash,masg)
    print(hash)
