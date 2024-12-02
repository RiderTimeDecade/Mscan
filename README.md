# Mscan

<div align="center">

![Logo](path/to/logo.png)

一款功能强大的内网安全扫描工具，集成端口扫描、服务识别、漏洞检测等功能。

[![Python Version](https://img.shields.io/badge/python-3.7+-blue)](https://www.python.org/)
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
  - SSH 弱口令检测
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
git clone https://github.com/yourusername/mscan.git
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
```

<details>
<summary>📸 扫描结果展示</summary>

![扫描结果](image.png)
![Web识别](image-1.png)
![报告展示](image-2.png)

</details>

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

# SSH 弱口令检测
mscan -i 192.168.1.1 -p 22 --user-file users.txt --pass-file pass.txt

# 生成 HTML 报告
mscan -i 192.168.1.1 -o report.html
```

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
--no-ssh             禁用SSH检测
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
│       ├── http_utils.py    # HTTP 工具
│       ├── logger.py        # 日志模块
│       └── progress.py      # 进度显示
├── data/              # 数据文件
│   └── cms_finger.db  # CMS 指纹库
└── pocs/              # POC 脚本
    └── examples/      # POC 示例
```

## 🔧 自定义 POC 开发

您可以参考 `pocs/examples/example_poc.py` 开发自己的 POC：

```python
from core.poc import BasePOC

class CustomPOC(BasePOC):
    def __init__(self):
        super().__init__()
        self.name = "Custom POC Name"
        self.description = "POC Description"
        
    def verify(self, target):
        # 实现验证逻辑
        return self.result
```

详细开发指南请参考 [POC 开发文档](docs/poc_guide.md)

## ⚡ 性能建议

- 生产环境建议使用较小线程数（-t 50）
- 全端口扫描耗时较长，建议使用 common 模式
- 大规模扫描时注意目标网络带宽
- 使用 -v 参数可查看详细扫描进度

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request！详见 [贡献指南](CONTRIBUTING.md)。

## 📜 开源协议

本项目采用 [MIT](LICENSE) 开源协议。

## 👨‍💻 作者

**Mscan** © [mzq](https://github.com/yourusername)  

---

> [个人博客](https://your-blog.com) · GitHub [@yourusername](https://github.com/yourusername) · Email mzq@example.com
