from pyDes import *
from random import randint
import struct
import numpy as np
import math
from pyasn1.type import univ, namedtype, tag
from pyasn1.codec.native.decoder import decode
from pyasn1.codec.native.encoder import encode
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
import base64
import hashlib, binascii
from shutil import copyfile
import msvcrt as m

KEY_FOR_3DES = b"NVB)*ONCHOV!H(BKV@!SNV58"



class RsaFile(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('alg_id', univ.OctetString()),
        namedtype.NamedType('key_id', univ.OctetString()),
        namedtype.NamedType('n', univ.Integer()),
        namedtype.NamedType('e', univ.Integer()),
        namedtype.NamedType('c', univ.Integer())
    )


class RsaKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('n', univ.Integer()),
        namedtype.NamedType('e', univ.Integer())
    )


# class FileSequence(univ.Sequence):
#     componentType = univ.Set(
#
#         namedtype.NamedType('n', univ.Integer()),
#         namedtype.NamedType('e', univ.Integer()),
#         namedtype.NamedType('c', univ.OctetString())
#     )

def extend_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extend_gcd(b % a, a)
        return g, y - (b // a) * x, x


def mul_inver(b, n):
    g, x, _ = extend_gcd(b, n)
    if g == 1:
        return (x % n + n) % n


def euclid_alg(a, b):
    while a != 0 and b != 0:
        if a > b:
            a = a % b
        else:
            b = b % a

    return a + b


def get_primes(top):
    lst = [2]
    for i in range(3, top + 1, 2):
        if (i > 10) and (i % 10 == 5):
            continue
        for j in lst:
            if j * j - 1 > i:
                lst.append(i)
                break
            if (i % j == 0):
                break
        else:
            lst.append(i)
    np.array(lst)
    return lst

def mod_pow(a, p, m):
    result = 1
    while p > 2:
        if p % 2 == 0:
            a = (a ** 2) % m
            p = p // 2
        else:
            result = (result * a) % m
            p = p - 1
    a = (a ** p) % m
    result = (result * a) % m
    return result

def RSA_encrypt(n, e, data):
    return mod_pow(data, e, n)


def RSA_decrypt(n, d, data):
    return mod_pow(data, d, n)


def TRI_DES_Scenario(n, e, d, data):

    # to asn1
    public_key = decode({'n': n, 'e': e}, asn1Spec=RsaKey())
    der_public_key = der_encode(public_key)

    # send public key
    with open('public_key', 'wb') as key_file:
        key_file.write(der_public_key)
    # recieve public key
    with open('public_key', 'rb') as key_file:
        public_key = key_file.read()

    # from asn1 get e,n
    public_key, _ = der_decode(public_key, asn1Spec=RsaKey())
    public_key = encode(public_key)
    e = public_key['e']
    n = public_key['n']

    # encrypt 3DES's key by RSA
    key_as_number = int.from_bytes(KEY_FOR_3DES, 'big')
    rsa_ecnrypted_key = RSA_encrypt(n, e, key_as_number)
    #print(rsa_ecnrypted_key)

    # to asn1
    open_key = decode({'alg_id':b'0001', 'key_id':b'key_for_3des','n': n, 'e': e, 'c':rsa_ecnrypted_key}, asn1Spec=RsaFile())
    der_file_with_3DES_key = der_encode(open_key)

    # send encrypted 3DES's key
    with open('file_with_3des_key', 'wb') as file:
        file.write(der_file_with_3DES_key)

    # recieve encrypted 3DES's key
    with open('file_with_3des_key', 'rb') as file:
        encrypted_3DES_key = file.read()

    # from asn1 get c
    encrypted_3DES_key, _ = der_decode(encrypted_3DES_key, asn1Spec=RsaFile())
    encrypted_3DES_key = encode(encrypted_3DES_key)
    c = encrypted_3DES_key['c']

    # rsa decrypt
    tri_des_key = RSA_decrypt(n, d, c)

    # encrypt data with 3DES
    tri_des_key = tri_des_key.to_bytes((tri_des_key.bit_length() + 7) // 8, 'big')
    tri_des = triple_des(tri_des_key, CBC, b"AWDADADA", pad=None, padmode=PAD_PKCS5)
    encrypted = tri_des.encrypt(data)
    #print(encrypted)

    # send encrypted data
    with open('ciphertext', 'wb') as ciphertext_file:
        ciphertext_file.write(encrypted)

    # recieve encrypted data
    with open('ciphertext', 'rb') as ciphertext_file:
        ciphertext = ciphertext_file.read()

    # decrypt data
    tri_des = triple_des(KEY_FOR_3DES, CBC, b"AWDADADA", pad=None, padmode=PAD_PKCS5)
    opentext = tri_des.decrypt(ciphertext)

    with open('decrypted_data', 'wb') as data:
       data.write(opentext)

def SHA_1_Scenario(n, e, d, data):
    # make digest
    md = hashlib.sha1()
    md.update(data)
    md = md.digest()
    # to asn1
    public_key = decode({'n': n, 'e': e}, asn1Spec=RsaKey())
    der_public_key = der_encode(public_key)

    # send public key
    with open('public_key', 'wb') as key_file:
        key_file.write(der_public_key)
    # recieve public key
    with open('public_key', 'rb') as key_file:
        public_key = key_file.read()

    # from asn1 get e,n
    public_key, _ = der_decode(public_key, asn1Spec=RsaKey())
    public_key = encode(public_key)
    e = public_key['e']
    n = public_key['n']

    #encrypt hash with RSA
    hash_as_number = int.from_bytes(md, 'big')
    rsa_ecnrypted_hash = RSA_encrypt(n, d, hash_as_number)

    # to asn1
    file_with_hash = decode({'alg_id':b'0006', 'key_id':b'key_for_sha','n': n, 'e': e, 'c':  rsa_ecnrypted_hash}, asn1Spec=RsaFile())
    der_file_with_hash = der_encode(file_with_hash)

    # send encrypted 3DES's key
    with open('file_with_hash', 'wb') as file:
        file.write(der_file_with_hash)

    # recieve encrypted 3DES's key
    with open('file_with_hash', 'rb') as file:
        encrypted_hash = file.read()


    # from asn1 get c
    encrypted_hash, _ = der_decode(encrypted_hash, asn1Spec=RsaFile())
    encrypted_hash = encode(encrypted_hash)
    c = encrypted_hash['c']

    # rsa decrypt
    hash = RSA_decrypt(n, e, c)
    hash =  hash.to_bytes(( hash.bit_length() + 7) // 8, 'big')

    # send file
    copyfile("data", "accepted_data")

    input("Continue?\n")

    # compare hashes
    path = "accepted_data"
    file = open(path, "rb")
    data = file.read()
    file.close()

    md = hashlib.sha1()
    md.update(data)
    md = md.digest()

    if(hash == md):
        print('Hashes matches\n')
    else:
        print('File corrupted\n')




if __name__ == "__main__":
    path = input("Enter path: ")
    #path = "data"
    file = open(path, "rb")
    data = file.read()
    file.close()

    #file = open("primes.txt", "r")
    #primes = file.readlines()
    #file.close()
    q = 192469981493128082197660102426797571253
    p = 231120049688016901212141732768631275781
    #while(q == p):
        #q = int(primes[randint(0, len(primes) - 1)])
        #p = int(primes[randint(0, len(primes) - 1)])
    n = p * q
    #print(n)
    euler = (p - 1) * (q - 1)
    #e = randint(2, euler - 1)
    #while euclid_alg(e, euler) != 1:
        #e = randint(2, euler - 1)
    e = 16115074252450668020380083911951303740962102875320971493812525689183929018303
    #print(e)
    d = mul_inver(e, euler)
    #print(d)
    print("Module: {}".format(n))
    print("Public exponent: {}".format(e))
    print("Private exponent: {}".format(d))
    while(True):
        point = input("1 - encrypt, 2 - massage digest, 3 - exit\n")
        if(point == "1"):
            TRI_DES_Scenario(n, e, d, data)
        elif(point == "2"):
            SHA_1_Scenario(n, e, d, data)
        elif(point == "3"):
            exit()
        else:
            print("Wrong!\n")

    #prime_array = get_primes(TOP)
    #np.save("primes", prime_array)
    #prime_array = np.load("primes.npy")
    #for elem in prime_array:
        #print(elem)

    #print("{} {}\n".format(e, n))
    #print("{} {}\n".format(d, n))


