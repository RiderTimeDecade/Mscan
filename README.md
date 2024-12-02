# Mscan

<div align="center">

<img src="https://raw.githubusercontent.com/RiderTimeDecade/Mscan/main/assets/logo.png" width="120" height="120" alt="Mscan Logo">

一款功能强大的内网安全扫描工具，集成端口扫描、服务识别、漏洞检测等功能。

[![Python Version](https://img.shields.io/badge/python-3.9+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/yourusername/mscan?style=social)](https://github.com/yourusername/mscan)

[English](README_EN.md) | 简体中文 | [使用文档](docs/guide.md) | [更新日志](CHANGELOG.md)

</div>

## ✨ 特性

- 🚀 **高性能扫描**
  - 智能存活检测
  - 自适应并发控制
  - 精准指纹识别
  - 低误报率

- 🎯 **多样化功能**
  - 端口扫描（支持 IP、CIDR、范围）
  - Web 服务识别（CMS、中间件、框架）
  - SSH/FTP 弱口令检测
  - 自定义 POC 漏洞扫描

- 📊 **专业报告**
  - 美观的 Web 界面
  - 可交互数据表格
  - 详细扫描结果
  - 资产统计分析

## 🚀 快速开始

### 环境要求

- Python 3.9+
- pip 包管理器

### 安装

```bash
# 方式一：pip 安装（推荐）
pip install mscan

# 方式二：源码安装
git clone https://github.com/RiderTimeDecade/Mscan.git
cd mscan
python setup.py install
```

### 使用示例

```bash
# 扫描单个目标
mscan -i 192.168.1.1

# 扫描网段
mscan -i 192.168.1.0/24 -m common

# Web 服务识别
mscan -u http://example.com

# SSH 弱口令检测
mscan -i 192.168.1.1 -p 22 --ssh-brute

# FTP 弱口令检测
mscan -i 192.168.1.1 -p 21 --ftp-brute
```

## 📚 使用指南

### 扫描目标格式

- 单个IP：`192.168.1.1`
- CIDR：`192.168.1.0/24`
- IP范围：`192.168.1.1-192.168.1.254`
- 文件导入：`@targets.txt`
- URL：`http://example.com`

### 常用命令

```bash
# 常用端口扫描
mscan -i 192.168.1.0/24 -m common

# 全端口扫描
mscan -i 192.168.1.1 -m full

# SSH 弱口令检测（使用内置字典）
mscan -i 192.168.1.1 -p 22 --ssh-brute

# SSH 弱口令检测（自定义字典）
mscan -i 192.168.1.1 -p 22 --ssh-brute --user-file users.txt --pass-file pass.txt

# FTP 弱口令检测（使用内置字典）
mscan -i 192.168.1.1 -p 21 --ftp-brute

# FTP 弱口令检测（自定义字典）
mscan -i 192.168.1.1 -p 21 --ftp-brute --user-file users.txt --pass-file pass.txt

# 生成 HTML 报告
mscan -i 192.168.1.1 -o report.html
```

### 内置字典说明

#### SSH 默认字典
- 用户名：root, admin, ubuntu 等系统和服务默认用户
- 密码：空密码、弱密码、常见组合等

#### FTP 默认字典
- 用户名：anonymous, ftp, admin 等FTP常见用户
- 密码：空密码、anonymous@、弱密码等

<details>
<summary>📋 完整参数说明</summary>

```
-h, --help            显示帮助信息
-i, --ip IP          目标IP/CIDR/范围
-u, --url URL        目标URL
-m, --mode MODE      扫描模式 (common/minimal/full)
-p, --ports PORTS    自定义端口
-t, --threads N      线程数 (默认: 500)
-o, --output FILE    输出文件
-v, --verbose        详细输出
--no-web             禁用Web识别
--ssh-brute          启用SSH弱口令检测
--ftp-brute          启用FTP弱口令检测
--user-file FILE     用户名字典
--pass-file FILE     密码字典
--report-dir DIR     报告目录
```

</details>

## 📦 项目结构

```
mscan/
├── core/               # 核心功能模块
│   ├── scanner.py     # 扫描器实现
│   └── poc.py         # POC 基类
├── lib/               # 功能库
│   ├── scanners/      # 各类扫描器
│   └── utils/         # 工具函数
├── config/            # 配置文件
│   └── settings.py    # 全局配置
├── data/              # 数据文件
│   └── cms_finger.db  # CMS 指纹库
└── pocs/              # POC 脚本
    └── examples/      # POC 示例
```

## ⚡ 性能建议

- 生产环境建议使用较小线程数（-t 50）
- 全端口扫描耗时较长，建议使用 common 模式
- 大规模扫描时注意目标网络带宽
- 使用 -v 参数可查看详细扫描进度
- 弱口令检测建议使用自定义小型字典提高效率

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！详见 [贡献指南](CONTRIBUTING.md)。

## 📜 开源协议

本项目采用 [MIT](LICENSE) 开源协议。

## 👨‍💻 作者

**Mscan** © [mzq](https://github.com/yourusername)  

---

> [个人博客](https://your-blog.com) · GitHub [@yourusername](https://github.com/yourusername) · Email mzq@example.com
