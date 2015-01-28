#!/usr/bin/env python

import blocktrail
import simplejson as json
import binascii
import unicodedata
import utils

API_KEY, API_SECRET = '298eddcd3aee06c0a1a50a8fb2b13607a833eb97', '90dd4ecd0c390e62647728fd5ebbb45c59e5feb1'
BASE_URL_HTTPS = 'https://api.blocktrail.com/v1/BTC'
BASE_URL = BASE_URL_HTTPS[:4] + BASE_URL_HTTPS[5:]

# Signature: 'keyId="API_KEY" algorithm="hmac-sha256" headers="(request-target) Date Content-MD5" signature="GENERATE_SIGNATURE"'
# 14zWNsgUMmHhYx4suzc2tZD6HieGbkQi5s

client = blocktrail.APIClient(api_key=API_KEY, api_secret=API_SECRET, network="BTC")


def getTxnOutputs(txid, stripped=False):
    """Take TxID and return a list of hex script (OP Data).
    If stripped = True, return list of hex values stripped of pre/appended OP codes
    """
    obj = client.transaction(txid)
    outputs = (client.transaction(txid)).get('outputs')
    hashes = [t['script'] for t in outputs]
    # outputs = obj.get('outputs')
    # pkhOutputs = [(outputs[x].get('script')).encode() for x in range(len(outputs))]
    # CHECK OP VALUES (send 'script_hex')
    if not stripped:
        return hashes
    elif stripped:
        return stripOPCodes(hashes)

# block height 0
def getCoinbaseData(blockheight=0, decode=False):
    """Take blockheight (genesis block = 0) and return coinbase hex data.
    If decode=True return coinbase as ASCII text."""
    assert isinstance(blockheight, int) and blockheight < 400000
    obj = client.block_transactions(blockheight)
    cbdata = (client.block_transactions(blockheight)).get('data')
    assert cbdata.has_key('is_coinbase')
    coinbase_hex = (((cbdata).get('inputs'))[0]).get('script_signature')
    # '04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73'
    if decode:
        return coinbase_hex.decode('hex')
    else:
        return coinbase_hex

#
def checkOPCode(hex_data):
    """Takes 'script' from API, checks OP code and returns a tuple of (OPCODE, hex data)"""

    if isinstance(hex_data, (str, unicode)):
        return checkOPCode()
    if isinstance(hex_data, list):
        # OP_RETURN
        s = str(hex_data[0]).replace('0x','')

# Should be a list with len = 1
def is_op_return(data_item):
    """Checks script is for an OP_RETURN Txn and returns True if so."""
    return (len(data_item) == 1 and ('RETURN' in str(data_item[0])))

# u'DUP HASH160 0x14 0x223339365ce2809c5468657265206973206e6f74 EQUALVERIFY CHECKSIG'
def is_op_dup(data_item):
    """Checks script is for a standard Txn and returns True if it is"""
    a,b,c,d,e,f = str(data_item).split()
    assert (len(d) == int(c[2:], 16))
    return ('DUP' and 'HASH160' and 'EQUALVERIFY' and 'CHECKSIG' in data_item)

def stripOPCodes(txn_obj):
    """Strip OP codes from hex data (eg pubkeyScript) leaving 20 bytes of hex data returned as a string, or list of strings"""
    if isinstance(txn_obj, list):
        hashs = [x for x in txn_obj if is_op_dup()]
        # CHECK 76A914 / 88AC
        return map(lambda x: x[6:-4], hashes)

    # else:
    #     return txn_obj[6:-4] if (str(txn_obj).startswith('76a914') and str(txn_obj).endswith('88ac')) else txn_obj

def Main():
    mandellaTxID = '8881a937a437ff6ce83be3a89d77ea88ee12315f37f7ef0dd3742c30eef92dba'
    mandellaTxn = getTxnOutputs(mandellaTxID, stripped=True)
    txnlist=map(lambda x: unicodedata.normalize('NFKD', x).encode('ascii','ignore'), txns)
    txnlist2=map(lambda x: x[6:-4], txnlist)

Main()