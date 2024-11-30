import json
import os
from datetime import datetime
from typing import Dict, List, Any
from colorama import Fore, Style

class OutputFormatter:
    @staticmethod
    def to_json(results: Dict, filename: str) -> None:
        """输出JSON格式"""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)

    @staticmethod
    def to_html(scan_results: Dict, filename: str) -> None:
        """生成HTML报告"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Mscan 扫描报告</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css" rel="stylesheet">
            <link href="https://fonts.googleapis.com/css2?family=SF+Pro+Display:wght@400;500;600&display=swap" rel="stylesheet">
            <style>
                :root {{
                    --apple-bg: #ffffff;
                    --apple-card: #f5f5f7;
                    --apple-text: #1d1d1f;
                    --apple-accent: #0066cc;
                    --apple-success: #28cd41;
                    --apple-danger: #ff3b30;
                    --apple-warning: #ff9500;
                }}
                
                body {{
                    font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont, sans-serif;
                    background-color: var(--apple-bg);
                    color: var(--apple-text);
                    line-height: 1.5;
                }}
                
                .container {{
                    max-width: 1200px;
                    padding: 2rem;
                }}
                
                h1 {{
                    font-weight: 600;
                    font-size: 2.5rem;
                    margin-bottom: 1.5rem;
                }}
                
                .card {{
                    background: var(--apple-card);
                    border: none;
                    border-radius: 1rem;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
                    margin-bottom: 2rem;
                    overflow: hidden;
                }}
                
                .card-header {{
                    background: var(--apple-bg);
                    border-bottom: 1px solid rgba(0,0,0,0.05);
                    padding: 1.25rem 1.5rem;
                }}
                
                .card-title {{
                    font-weight: 500;
                    font-size: 1.25rem;
                    margin: 0;
                    color: var(--apple-text);
                }}
                
                .table {{
                    margin: 0;
                }}
                
                .table th {{
                    font-weight: 500;
                    color: var(--apple-text);
                    border-bottom-width: 1px;
                }}
                
                .table td {{
                    vertical-align: middle;
                }}
                
                .vulnerability {{ color: var(--apple-danger); }}
                .service {{ color: var(--apple-accent); }}
                .technology {{ color: var(--apple-success); }}
                .port-open {{ 
                    color: var(--apple-success);
                    font-weight: 500;
                }}
                
                .badge {{
                    font-weight: 500;
                    padding: 0.4em 0.8em;
                    border-radius: 1rem;
                }}
                
                .bg-danger {{ background-color: var(--apple-danger) !important; }}
                .bg-warning {{ background-color: var(--apple-warning) !important; }}
                .bg-info {{ background-color: var(--apple-accent) !important; }}
                
                a {{
                    color: var(--apple-accent);
                    text-decoration: none;
                }}
                
                a:hover {{
                    text-decoration: underline;
                }}
                
                .dataTables_wrapper .dataTables_paginate .paginate_button.current {{
                    background: var(--apple-accent);
                    border-color: var(--apple-accent);
                    color: white !important;
                    border-radius: 0.5rem;
                }}
                
                .dataTables_wrapper .dataTables_paginate .paginate_button:hover {{
                    background: var(--apple-accent);
                    border-color: var(--apple-accent);
                    color: white !important;
                }}
                
                .dataTables_wrapper .dataTables_length select,
                .dataTables_wrapper .dataTables_filter input {{
                    border: 1px solid #e5e5e5;
                    border-radius: 0.5rem;
                    padding: 0.375rem 0.75rem;
                }}
                
                .text-muted {{
                    color: #86868b !important;
                }}
                
                /* 暗色模式支持 */
                @media (prefers-color-scheme: dark) {{
                    :root {{
                        --apple-bg: #000000;
                        --apple-card: #1c1c1e;
                        --apple-text: #f5f5f7;
                    }}
                    
                    .table {{
                        color: var(--apple-text);
                    }}
                    
                    .table td, .table th {{
                        border-color: rgba(255,255,255,0.1);
                    }}
                    
                    .card-header {{
                        border-color: rgba(255,255,255,0.1);
                    }}
                    
                    .dataTables_wrapper .dataTables_length select,
                    .dataTables_wrapper .dataTables_filter input {{
                        background: var(--apple-card);
                        border-color: rgba(255,255,255,0.1);
                        color: var(--apple-text);
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Mscan 扫描报告</h1>
                <p class="text-muted">生成时间: {now}</p>
                
                <!-- 端口扫描结果 -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">端口扫描结果</h3>
                    </div>
                    <div class="card-body">
                        <table id="portTable" class="table table-hover">
                            <thead>
                                <tr>
                                    <th>IP地址</th>
                                    <th>开放端口</th>
                                    <th>服务</th>
                                </tr>
                            </thead>
                            <tbody>
                                {OutputFormatter._generate_port_rows(scan_results.get('ports', {}))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Web服务 -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">Web服务</h3>
                    </div>
                    <div class="card-body">
                        <table id="webTable" class="table table-hover">
                            <thead>
                                <tr>
                                    <th>目标</th>
                                    <th>网站标题</th>
                                    <th>服务器</th>
                                    <th>技术栈</th>
                                    <th>状态码</th>
                                </tr>
                            </thead>
                            <tbody>
                                {OutputFormatter._generate_web_rows(scan_results.get('web', {}))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- SSH服务 -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">SSH服务</h3>
                    </div>
                    <div class="card-body">
                        <table id="sshTable" class="table table-hover">
                            <thead>
                                <tr>
                                    <th>目标</th>
                                    <th>端口</th>
                                    <th>用户名</th>
                                    <th>密码</th>
                                </tr>
                            </thead>
                            <tbody>
                                {OutputFormatter._generate_ssh_rows(scan_results.get('ssh', {}))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- 漏洞信息 -->
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title">漏洞信息</h3>
                    </div>
                    <div class="card-body">
                        <table id="vulnTable" class="table table-hover">
                            <thead>
                                <tr>
                                    <th>目标</th>
                                    <th>漏洞类型</th>
                                    <th>危险等级</th>
                                    <th>漏洞描述</th>
                                </tr>
                            </thead>
                            <tbody>
                                {OutputFormatter._generate_vuln_rows(scan_results.get('vulnerabilities', []))}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>

            <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
            <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
            <script src="https://cdn.datatables.net/1.11.5/js/dataTables.bootstrap5.min.js"></script>
            <script>
                $(document).ready(function() {{
                    $('.table').DataTable({{
                        "order": [[0, "asc"]],
                        "pageLength": 25,
                        "language": {{
                            "search": "搜索:",
                            "lengthMenu": "显示 _MENU_ 条记录",
                            "info": "显示第 _START_ 至 _END_ 项结果，共 _TOTAL_ 项",
                            "infoEmpty": "显示第 0 至 0 项结果，共 0 项",
                            "infoFiltered": "(由 _MAX_ 项结果过滤)",
                            "paginate": {{
                                "first": "首页",
                                "last": "末页",
                                "next": "下一页",
                                "previous": "上一页"
                            }},
                            "zeroRecords": "没有匹配结果",
                            "emptyTable": "暂无数据"
                        }}
                    }});
                }});
            </script>
        </body>
        </html>
        """

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_template)

        print(f"{Fore.GREEN}[+] Report saved to {filename}{Style.RESET_ALL}")

    @staticmethod
    def _generate_web_rows(web_results: Dict) -> str:
        """生成Web服务表格行"""
        rows = []
        for key, data in web_results.items():
            ip, port = key.split(':')
            url = f"{'https' if port == '443' else 'http'}://{ip}:{port}"
            technologies = ', '.join(data.get('technologies', []))
            server = data.get('server', 'Unknown')
            title = data.get('title', 'Unknown')
            status = data.get('status_code', 0)
            
            row = f"""
                <tr>
                    <td><a href="{url}" target="_blank">{url}</a></td>
                    <td>{title}</td>
                    <td class="service">{server}</td>
                    <td class="technology">{technologies}</td>
                    <td>{status}</td>
                </tr>
            """
            rows.append(row)
        return '\n'.join(rows)

    @staticmethod
    def _generate_ssh_rows(ssh_results: Dict) -> str:
        """生成SSH服务表格行"""
        rows = []
        for ip, creds in ssh_results.items():
            for cred in creds:
                row = f"""
                    <tr>
                        <td>{ip}</td>
                        <td>{cred['port']}</td>
                        <td>{cred['username']}</td>
                        <td>{cred['password']}</td>
                    </tr>
                """
                rows.append(row)
        return '\n'.join(rows)

    @staticmethod
    def _generate_vuln_rows(vuln_results: List) -> str:
        """生成漏洞表格行"""
        severity_map = {
            'high': ('danger', '高危'),
            'medium': ('warning', '中危'),
            'low': ('info', '低危')
        }
        
        rows = []
        for vuln in vuln_results:
            severity = vuln.get('severity', 'low').lower()
            severity_class, severity_text = severity_map.get(severity, ('info', '未知'))
            
            row = f"""
                <tr>
                    <td>{vuln.get('target', '')}</td>
                    <td>{vuln.get('type', '')}</td>
                    <td><span class="badge bg-{severity_class}">{severity_text}</span></td>
                    <td>{vuln.get('description', '')}</td>
                </tr>
            """
            rows.append(row)
        return '\n'.join(rows)

    @staticmethod
    def _generate_port_rows(port_results: Dict) -> str:
        """生成端口扫描表格行"""
        rows = []
        for ip, ports in port_results.items():
            # 将端口按数字大小排序
            sorted_ports = sorted(ports)
            # 获取每个端口对应的服务
            services = [f"{port} ({OutputFormatter._get_service_name(port)})" for port in sorted_ports]
            
            row = f"""
                <tr>
                    <td>{ip}</td>
                    <td class="port-open">{', '.join(map(str, sorted_ports))}</td>
                    <td class="service">{', '.join(services)}</td>
                </tr>
            """
            rows.append(row)
        return '\n'.join(rows)

    @staticmethod
    def _get_service_name(port: int) -> str:
        """获取端口对应的服务名称"""
        common_ports = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return common_ports.get(port, 'Unknown')

    @staticmethod
    def save_results(results: Dict, filename: str) -> None:
        """保存扫描结果"""
        ext = os.path.splitext(filename)[1].lower()
        if ext == '.json':
            OutputFormatter.to_json(results, filename)
        elif ext == '.html':
            OutputFormatter.to_html(results, filename)
        else:
            # 默认使用HTML格式
            OutputFormatter.to_html(results, filename + '.html')