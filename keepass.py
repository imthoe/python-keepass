#!/usr/bin/env python
# Author: imthoe

from struct import *
from binascii import *
from itertools import chain, product
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes,padding
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
import sys,argparse,string

parser = argparse.ArgumentParser()
mode="bruteforce"

def verify():
    try:
        file_object = open(file_path,mode='rb')
    except:
        print(file_path+" is not a valid path")
        parser.exit()
    kdb_sig = unpack_from('<3I',file_object.read(),0)
    file_object.close()
    if(('0x9aa2d903','0xb54bfb67') == (hex(kdb_sig[0]),hex(kdb_sig[1]))):
        if args.verbose:
            print('[+] File is valid. Starting to crack!\n')
    else:
        print('[-] File is not a valid KeePass File')
        parser.exit()
    return;

def load_header(id):
    file_object = open(file_path,mode='rb')
    bytedata = file_object.read()[12:] #erste 12 Bytes sind Signatur
    file_object.close()

    for x in range(0,10):
        head_id = unpack_from('<b',bytedata)[0]
        head_len = unpack_from('<bh',bytedata)[1]
        bytedata = bytedata[3:]
        if(id != 0):
            head_data = unpack_from(str(head_len)+'s',bytedata)[0]
        else:
            head_data = unpack_from(str(len(bytedata)-head_len)+'s',bytedata,head_len)[0]
        bytedata = bytedata[head_len:]
        if(id == head_id):
            return (head_data)

# data has to be bytes

def sha256(data):
    sha256 = hashes.Hash(hashes.SHA256(),backend=default_backend())
    sha256.update(data)
    final_data = sha256.finalize()
    return final_data

def aes256(key,iv,data,mode='ECB'):
    if mode == 'CBC':
        cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend())
    elif mode == 'ECB':
        cipher = Cipher(algorithms.AES(key),modes.ECB(),backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return encrypted

def aes256_decrypt(key,iv,data):
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    return decrypted

def aes256_exp(key,iv,data,rounds):
    final_data = data
    for x in range(rounds):
        final_data = aes256(key,iv,final_data,'ECB')
    return final_data

def create_key(password):
    credentials = sha256(sha256(password.encode('utf-8')))
    transformed_credentials = sha256(aes256_exp(transform_seed,init_vector,credentials,transform_rounds))
    key = sha256(master_seed + transformed_credentials)
    return key
	
def try_pass(password,status=0.0,verbose=True):
    data = aes256_decrypt(create_key(password),init_vector,crypted_data)
    if data[:32] == start_bytes:
        sys.stdout.write('\r[+] SUCCESS! Password is '+password+'\n')
        sys.stdout.flush()
        parser.exit()
    else:
        if verbose:
            sys.stdout.write("[-] "+ password+"\n")
            sys.stdout.write("[+] Progress: {0:.4f}".format(status*100)+"%")
            sys.stdout.write("\033[F")
            sys.stdout.write(40*" "+"\r")

def bruteforce(mode="wordlist",verbose=True):

    if mode == "wordlist":
        lst = list()
        with open(wordlist_path,'r') as f:
            for line in f:
                lst.append(line.rstrip('\n').rstrip('\r'))
        num_lines = len(lst)
        for x in range(0,num_lines):
            def password():
                return lst[x]
            
            status = float(x) / num_lines
            try:
                try_pass(password(),status,verbose)
            except UnicodeDecodeError:
                # Couldn't encode the given password
                None
        print("[-] No Password was found")
    elif mode == "bruteforce":
        def bruteforce(charset, maxlength):
            return (''.join(candidate)
                for candidate in chain.from_iterable(product(charset, repeat=i)
                for i in range(1, maxlength + 1)))
        
        for pwd in bruteforce(string.ascii_letters+string.digits, bruteforce_maxlength):
            try_pass(pwd)
    return

# Parser

parser.add_argument("-w","--wordlist",help="wordlist file to use")
parser.add_argument("file",help="Keepass file to crack")
parser.add_argument("-v","--verbose",help="verbose ouput",action="store_true")
args = parser.parse_args()

if args.wordlist:
    mode="wordlist"
    wordlist_path=args.wordlist
else:
    mode="bruteforce"

file_path=args.file

# Loading all headers

master_seed = load_header(4)
transform_seed = load_header(5)
transform_rounds = unpack_from('<L',load_header(6))[0]
init_vector = load_header(7)
start_bytes = load_header(9)
crypted_data = load_header(0)
crypted_start_bytes = crypted_data[:32]

# Starting the script

bruteforce_maxlength = 10
verify()
bruteforce(mode,args.verbose)
