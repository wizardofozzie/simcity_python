#!/usr/bin/env python
import hashlib
import struct
import unicodedata
import codecs
from sys import version
#from __future__ import division

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}

# PYBITCOINTOOLS

def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")

def lpad(msg, symbol, length):
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg


def encode(val, base, minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result = ""
    while val > 0:
        result = code_string[val % base] + result
        val //= base
    return lpad(result, code_string[0], minlen)


def decode(string, base):
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += code_string.find(string[0])
        string = string[1:]
    return result


def changebase(string, frm, to, minlen=0):
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)
    return encode(decode(string, frm), to, minlen)

# KEN SHIRRIFF

def base58encode(n):
    result = ''
    while n > 0:
        result = b58[n%58] + result
        n /= 58
    return result

def base58decode(s):
    result = 0
    for i in range(0, len(s)):
        result = result * 58 + b58.index(s[i])
    return result

def base256encode(n):
    result = ''
    while n > 0:
        result = chr(n % 256) + result
        n /= 256
    return result

def base256decode(s):
    result = 0
    for c in s:
        result = result * 256 + ord(c)
    return result

def countLeadingChars(s, ch):
    count = 0
    for c in s:
        if c == ch:
            count += 1
        else:
            break
    return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
    s = chr(version) + payload
    checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    result = s + checksum
    leadingZeros = countLeadingChars(result, '\0')
    return '1' * leadingZeros + base58encode(base256decode(result))

def base58CheckDecode(s):
    """Takes a base58Check string and returns """
    leadingOnes = countLeadingChars(s, '1')
    s = base256encode(base58decode(s))
    result = '\0' * leadingOnes + s[:-4]
    chk = s[-4:]
    checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
    assert(chk == checksum)
    version = result[0]
    return result[1:]

def is_odd(s):
    '''Returns True if hex or binary string needs padding with 0'''
    return len(s) % 2 == 1

def decodeUnicodeToASCII(unicode_obj):
    '''Decode unicode object to ASCII'''
    if isinstance(unicode_obj, str):
        return unicodedata.normalize('NFKD', unicode_obj).encode('ascii','ignore')
        #lambda x: unicodedata.normalize('NFKD', x).encode('ascii','ignore')
    elif isinstance(unicode_obj, list):
        return map(decodeUnicodeToASCII, unicode_obj)

def stripOPCodes(txn_obj):
    """Strip OP codes from hex data (eg pubkeyScript) leaving 20 bytes of hex data returned as a string, or list of strings"""
    if isinstance(txn_obj, list):
        # CHECK 76A914 / 88AC
        return map(lambda x: x[6:-4], txn_obj)
    else:
        return txn_obj[6:-4] if (str(txn_obj).startswith('1976a9') and str(txn_obj).endswith('88ac')) else txn_obj

# def formatPubKeyHash(pubkeyhash):
#     '''Checks pubkeyhash and strips OP code data if required, otherwise returns padded hex string'''
#     #if isinstance(pubkeyhash, str):
#     if isinstance(pubkeyhash, list):
#         newList = []
#         newList = map(lambda y: formatPubKeyHash(y), pubkeyhash)
#         assert len(pubkeyhash) == len(newList)
#         return newList
#     else:
#         pkh = str(pubkeyhash)
#         return pkh[6:-4] if (pkh.startswith('1976a9') and pkh.endswith('88ac')) else pkh

def padHex(hexString):
    """Takes a hex string and pads with leading zeroes if required."""
    if is_odd(hexString):
        return hexString.zfill(len(hexString) + 1)
    else:
        return hexString

def convertEndianess(hexString):
    """Takes string of Little/Big Endian hex, converts Endianess, returns hex string."""
    if version < '3':
        import codecs
        S = hexString
        return codecs.encode(codecs.decode(S, 'hex')[::-1], 'hex').decode()
    elif not version < '3':
        s = hexString
        return codecs.encode(codecs.decode(s, 'hex')[::-1], 'hex').decode()
