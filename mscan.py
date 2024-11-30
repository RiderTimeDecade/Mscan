#!/usr/bin/env python3
import sys
import os
import argparse
import logging
from datetime import datetime
from colorama import init, Fore, Style

# 初始化 colorama
init()

# 添加项目根目录到 Python 路径
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(ROOT_DIR)

from lib.scanners.port_scanner import IPScanner
from lib.scanners.web_scanner import CMSScanner
from lib.scanners.ssh_scanner import SSHBruteforce
from lib.utils.logger import setup_logger
from lib.utils.output import OutputFormatter
from config.settings import *

def parse_args():
    parser = argparse.ArgumentParser(
        description='Mscan - Multi-purpose Security Scanner',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # 目标参数
    target_group = parser.add_argument_group('Target')
    target_group.add_argument('-i', '--ip', help='Target IP/CIDR/Range')
    target_group.add_argument('-u', '--url', help='Target URL')
    target_group.add_argument('-f', '--file', help='Target file')
    
    # 扫描模式
    mode_group = parser.add_argument_group('Scan Mode')
    mode_group.add_argument('-m', '--mode', 
                           choices=list(DEFAULT_PORTS.keys()),
                           default='common',
                           help='Predefined port scan mode')
    mode_group.add_argument('-p', '--ports', help='Custom ports')
    
    # 模块控制
    module_group = parser.add_argument_group('Modules')
    module_group.add_argument('--no-web', action='store_true', help='Skip web detection')
    module_group.add_argument('--no-ssh', action='store_true', help='Skip SSH bruteforce')
    
    # 爆破选项
    brute_group = parser.add_argument_group('Brute Force')
    brute_group.add_argument('--user-file', help='Custom username file for SSH bruteforce')
    brute_group.add_argument('--pass-file', help='Custom password file for SSH bruteforce')
    
    # 输出选项
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-o', '--output', help='Output file path (e.g., report.html or report.json)')
    output_group.add_argument('--no-report', action='store_true', help='Disable HTML report generation')
    output_group.add_argument('--report-dir', default='reports', help='Directory to save reports')
    
    # 其他选项
    parser.add_argument('-t', '--threads', type=int, default=THREADS,
                      help='Number of threads')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Verbose output')
    
    return parser.parse_args()

def main():
    args = parse_args()
    logger = setup_logger(args.verbose)
    
    # 存储所有扫描结果
    all_results = {
        'ports': {},
        'web': {},
        'ssh': {},
        'vulnerabilities': []
    }
    
    try:
        # 端口扫描
        if args.ip:
            ports_str = DEFAULT_PORTS[args.mode] if args.mode else args.ports
            ports = [int(p.strip()) for p in ports_str.split(',')]
            
            port_scanner = IPScanner(threads=args.threads)
            scan_results = port_scanner.scan(args.ip, ports)
            
            if scan_results:
                # 保存端口扫描结果
                all_results['ports'] = scan_results
                
                # Web服务识别
                if not args.no_web:
                    web_scanner = CMSScanner()
                    web_results = web_scanner.scan(scan_results)
                    all_results['web'].update(web_results)
                
                # SSH爆破
                if not args.no_ssh:
                    ssh_ports = {}
                    for ip, ports in scan_results.items():
                        ssh_ports[ip] = {port for port in ports if port in {22, 222, 2222, 22222}}
                    
                    if ssh_ports:
                        ssh_scanner = SSHBruteforce(threads=args.threads)
                        ssh_results = ssh_scanner.scan(
                            ssh_ports,
                            userfile=args.user_file,
                            passfile=args.pass_file
                        )
                        all_results['ssh'].update(ssh_results)
        
        # URL扫描
        if args.url:
            web_scanner = CMSScanner()
            web_results = web_scanner.scan({args.url: {80}})
            all_results['web'].update(web_results)
            
        # 生成报告
        if not args.no_report:
            # 创建输出目录
            os.makedirs(args.report_dir, exist_ok=True)
            
            # 生成报告文件名
            if args.output:
                output_file = os.path.join(args.report_dir, args.output)
            else:
                # 使用目标信息和时间戳生成文件名
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                target_info = args.ip if args.ip else args.url if args.url else "scan"
                target_info = target_info.replace('/', '_').replace(':', '_')
                output_file = os.path.join(args.report_dir, f"mscan_{target_info}_{timestamp}.html")
            
            # 保存报告
            OutputFormatter.save_results(all_results, output_file)
            print(f"\n{Fore.GREEN}[+] Scan report saved to: {output_file}{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 