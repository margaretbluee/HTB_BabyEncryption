import binascii
import time

def encrypt(char):
    return (123 * char + 18) % 256

def decipher_w_loops(msg):
    og_msg = []
    for byte in msg:
        for i in range(1, 129):
            encrypted = encrypt(i)
            if encrypted == byte:
                og_msg.append(chr(i))
    return ''.join(og_msg)

def decipher_w_hashmap(msg):
    mapping = {encrypt(i): i for i in range(1, 129)}
    decrypted_chars = [chr(mapping[char]) for char in msg]
    return ''.join(decrypted_chars)

def decipher_w_reverse(ct):
    pt = []
    for char in ct:
        pt.append(((char - 18) * 179) % 256)  # Reverse of the encryption formula
    return bytes(pt).decode('utf-8')  # Convert bytes back to string

# Read the encrypted message from file
with open('./msg.enc', 'r') as f:
    encrypted_hex = f.read()

# Convert the hexadecimal encrypted message to bytes
encrypted_bytes = bytes.fromhex(encrypted_hex)




with open("msg.enc") as f:
    msg = binascii.unhexlify(f.read())

start = time.perf_counter()
deciphered_w_loops = decipher_w_loops(msg)
stop = time.perf_counter()
loop_time = (stop - start) * 1000

start = time.perf_counter()
deciphered_w_hashmap = decipher_w_hashmap(msg)
stop = time.perf_counter()
hashmap_time = (stop - start) * 1000

# Decipher with reverse
start = time.perf_counter()
decrypted_message = decipher_w_reverse(encrypted_bytes)
stop = time.perf_counter()
rev_time = (stop - start) * 1000

print(f'Reverse: { decrypted_message}')
print(f'Brute force: {deciphered_w_loops}')
print(f'Hashmap: {deciphered_w_hashmap}')
print(f'Time taken by brute force: {loop_time} ms')
print(f'Time taken by hashmap: {hashmap_time} ms')
print(f'Time taken by reverse: {rev_time} ms')
