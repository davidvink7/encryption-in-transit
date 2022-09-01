# Script to encrypt data with aes cbc mode
# Author: davidvink7

import argparse
import json
import logging
import requests
import yaml

from Crypto import Random
from Crypto.Cipher import AES

# Initialize logging
FORMAT = '%(asctime)s:%(name)s:%(levelname)s - %(message)s'
logging.basicConfig(format = FORMAT, filename='encrypt_post.log', level=logging.INFO)

# Initialize parsing of data string -- data string needs quotes
parser = argparse.ArgumentParser()
parser.add_argument("data", help="data string")

# Load key and endpoint
with open('config.yaml', 'r') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

api_key = config['api_key']
endpoint = config['data_endpoint']
key = config['key']
test_data = ‘test’
BS = AES.block_size

def encrypt(raw, key):
    raw = pad(raw)
    iv = Random.new().read(BS)
    cipher = AES.new(key.encode("utf8"), AES.MODE_CBC, iv)
    res = iv + cipher.encrypt(raw.encode())
    res = base64.b64encode(res).decode('utf-8')
    return { 'data': res, 'api_key': api_key }

## Testing
def decrypt(output):
    enc = b64decode(output['data'])
    iv = enc[:AES.block_size]
    cipher = AES.new(key.encode("utf8"), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
    return decrypted

def post(data):
    try:
        res = requests.post(url = endpoint, data = data)
        logging.info({'code': res.status_code, 'txt': res.text})
    except:
        logging.exception('Exception occurred')

def pad(raw):
    return raw + (BS - len(raw) % BS) * chr(BS - len(raw) % BS)

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def main():
    try:
        string_data = json.dumps(test_data)
        post(encrypt(string_data, key))
    except:
        logging.exception('Exception occurred')

if __name__ == "__main__":
    main()

