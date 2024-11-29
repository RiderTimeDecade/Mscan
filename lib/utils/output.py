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
        # 获取当前时间
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # HTML模板
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Mscan Scan Report</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
            <link href="https://cdn.datatables.net/1.11.5/css/dataTables.bootstrap5.min.css" rel="stylesheet">
            <style>
                .vulnerability {{ color: #dc3545; }}
                .service {{ color: #0d6efd; }}
                .technology {{ color: #198754; }}
            </style>
        </head>
        <body>
            <div class="container mt-5">
                <h1 class="mb-4">Mscan Scan Report</h1>
                <p class="text-muted">Generated at: {now}</p>
                
                <!-- Web Services -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3 class="card-title">Web Services</h3>
                    </div>
                    <div class="card-body">
                        <table id="webTable" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Target</th>
                                    <th>Title</th>
                                    <th>Server</th>
                                    <th>Technologies</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                {OutputFormatter._generate_web_rows(scan_results.get('web', {}))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- SSH Services -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3 class="card-title">SSH Services</h3>
                    </div>
                    <div class="card-body">
                        <table id="sshTable" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Target</th>
                                    <th>Port</th>
                                    <th>Username</th>
                                    <th>Password</th>
                                </tr>
                            </thead>
                            <tbody>
                                {OutputFormatter._generate_ssh_rows(scan_results.get('ssh', {}))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Vulnerabilities -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h3 class="card-title">Vulnerabilities</h3>
                    </div>
                    <div class="card-body">
                        <table id="vulnTable" class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Target</th>
                                    <th>Type</th>
                                    <th>Severity</th>
                                    <th>Description</th>
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
                    $('#webTable').DataTable({{
                        "order": [[0, "asc"]],
                        "pageLength": 25
                    }});
                    $('#sshTable').DataTable({{
                        "order": [[0, "asc"]],
                        "pageLength": 25
                    }});
                    $('#vulnTable').DataTable({{
                        "order": [[2, "desc"]],
                        "pageLength": 25
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
        rows = []
        for vuln in vuln_results:
            severity_class = {
                'high': 'danger',
                'medium': 'warning',
                'low': 'info'
            }.get(vuln.get('severity', 'low').lower(), 'info')
            
            row = f"""
                <tr>
                    <td>{vuln.get('target', '')}</td>
                    <td>{vuln.get('type', '')}</td>
                    <td><span class="badge bg-{severity_class}">{vuln.get('severity', '').upper()}</span></td>
                    <td>{vuln.get('description', '')}</td>
                </tr>
            """
            rows.append(row)
        return '\n'.join(rows)

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