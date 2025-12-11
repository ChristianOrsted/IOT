
# 物联网安全实验项目

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()
[![Language](https://img.shields.io/badge/language-C%20%7C%20Assembly%20%7C%20Python-orange.svg)]()

> 一个用于物联网安全研究和教育的综合性缓冲区溢出攻击演示项目

## 目录

- [项目概述](#项目概述)
- [实验环境](#实验环境)
- [项目结构](#项目结构)
- [安装说明](#安装说明)
- [使用方法](#使用方法)
- [核心组件](#核心组件)
- [安全声明](#安全声明)
- [参与贡献](#参与贡献)
- [联系方式](#联系方式)
- [开源许可](#开源许可)

## 项目概述

本项目展示了物联网环境中的多种缓冲区溢出攻击技术，为理解内存破坏漏洞和利用方法提供实践经验。该项目旨在作为学习底层安全机制和防御策略的教育资源。

**核心特性：**
- 多种缓冲区溢出攻击场景（bang、boom、fizz、smoke）
- 汇编级别的 payload 构造
- 自动化 payload 生成脚本
- 可重现的实验环境

## 实验环境

**操作系统与编译环境：**
```bash
Linux ORSTED-LAPTOP 5.15.167.4-microsoft-standard-WSL2
#1 SMP Tue Nov 5 00:21:55 UTC 2024 x86_64 GNU/Linux

gcc (Debian 14.2.0-19) 14.2.0
Copyright (C) 2024 Free Software Foundation, Inc.
```

**平台：** WSL2（Windows Subsystem for Linux）  
**发行版：** Kali Linux  
**架构：** x86_64

### 环境依赖

- GCC 编译器
- Python 3.x
- GDB 调试器（推荐）
- Make 工具

## 项目结构

```txt
IOT/
├── assembly/                 # 汇编源文件
│   ├── bang.s               # Bang 攻击汇编代码
│   ├── bang.o               # 编译后的目标文件
│   ├── boom.s               # Boom 攻击汇编代码
│   └── boom.o               # 编译后的目标文件
├── payload/                  # 二进制 payload 文件
│   ├── bang.bin             # Bang 攻击 payload
│   ├── boom.bin             # Boom 攻击 payload
│   ├── fizz.bin             # Fizz 攻击 payload
│   └── smoke.bin            # Smoke 攻击 payload
├── python/                   # Payload 生成脚本
│   ├── bang.py              # Bang payload 生成器
│   ├── boom.py              # Boom payload 生成器
│   ├── fizz.py              # Fizz payload 生成器
│   └── smoke.py             # Smoke payload 生成器
├── note/                     # 实验记录
│   ├── debug_log.txt        # 调试日志
│   └── note.txt             # 实验笔记
├── md/                       # 文档
│   └── note.md              # 技术笔记
├── Word/                     # 实验报告
│   └── 实验-内存溢出攻击-20240913.docx
├── main.c                    # 漏洞程序源代码
├── main                      # 编译后的可执行文件
├── r.sh                      # 环境配置脚本
└── README.md                 # 项目文档
```

## 安装说明

### 1. 克隆项目

```bash
git clone https://github.com/ChristianOrsted/IOT/.git
cd IOT
```

### 2. 配置环境

```bash
chmod +x r.sh
./r.sh
```
```bash
sudo sysctl -w kernel.randomize_va_space=0
```

### 3. 编译漏洞程序

```bash
gcc -o main main.c -fno-stack-protector -z execstack -no-pie
```

**编译参数说明：**
- `-fno-stack-protector`：禁用栈保护
- `-z execstack`：允许栈可执行
- `-no-pie`：禁用地址随机化

## 使用方法

### 生成 Payload

运行 Python 脚本生成二进制 payload：

```bash
# 生成 bang payload
python3 python/bang.py > payload/bang.bin

# 生成 boom payload
python3 python/boom.py > payload/boom.bin

# 生成 fizz payload
python3 python/fizz.py > payload/fizz.bin

# 生成 smoke payload
python3 python/smoke.py > payload/smoke.bin
```

### 执行攻击

```bash
# 示例：使用 bang payload 执行
./r.sh ./main test < payload/bang.bin
```

### 调试分析

使用 GDB 进行详细分析：

```bash
./r.sh gdb ./main
(gdb) run test < payload/bang.bin
(gdb) info registers
```

```bash
(gdb) layout asm # 打开反汇编窗口
(gdb) layout reg # 打开寄存器窗口
```

## 核心组件

### 汇编 Payload

手工编写的 x86_64 汇编 shellcode，用于不同的攻击场景。包含精心构造的指令序列，实现特定的攻击效果。

### Python 生成器

自动化脚本用于生成二进制 payload，支持参数自定义。可根据需要调整 payload 结构和内容。

### 漏洞程序

故意设计的存在缓冲区溢出漏洞的 C 程序，用于演示内存安全问题。

### 环境配置脚本

`r.sh` 确保在不同系统上建立一致的实验环境。


## 联系方式

**Yunchen XU**  
邮箱：446937472@qq.com

如有问题、建议或合作意向，欢迎联系。
