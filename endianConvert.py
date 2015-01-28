import codecs
from sys import version

def convertEndianess(hexString):
    """Takes string of Little/Big Endian hex, converts Endianess, returns hex string.
    """
    if version < '3':
        import codecs
        S = hexString
        return codecs.encode(codecs.decode(S, 'hex')[::-1], 'hex').decode()
    elif not version < '3':
        s = hexString
        return codecs.encode(codecs.decode(s, 'hex')[::-1], 'hex').decode()
