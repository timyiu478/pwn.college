# This is WIP

from pwn import *
import string
import requests




def random_printable_string(length=16):
    return ''.join(random.choice(string.printable) for _ in range(length))


know_cipher = bytes.fromhex("ad853569019db317f123b4010efb1394f483eb9a816e2c3f8f4b5d7898f5400e71c7ba0b6cb1060c47016ed88cfc7688486a8972c75aa2fc04090cdb8138c381")

cipher_blocks = [know_cipher[i:i+16] for i in range(0, len(know_cipher), 16)]

url = 'http://challenge.localhost/'



while True:
    guess = random_printable_string()
    
    response = requests.get(url + f"?query={guess}")
    print(response.text)
