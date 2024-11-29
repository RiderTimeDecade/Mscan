import ipaddress
from typing import List, Generator, Union, Set
import socket
import concurrent.futures
import logging
from lib.utils.logger import setup_logger
import sys
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Style
import threading
import time
import subprocess
import platform
import os
from concurrent.futures import ThreadPoolExecutor

# 初始化colorama
init()

class IPScanner:
    # 默认端口配置
    DEFAULT_PORTS = {
        'web': [80, 81, 443, 7001, 8000, 8080, 8089, 9000],  # Web服务端口
        'database': [1433, 1521, 3306, 5432, 6379, 27017],   # 数据库端口
        'remote': [22, 23, 3389],                            # 远程服务端口
        'common': [21, 22, 80, 81, 135, 139, 443, 445, 1433, 1521, 3306, 5432, 6379, 7001, 8000, 8080, 8089, 9000, 9200, 11211, 27017],  # 常见服务端口
        'full': list(range(1, 10001)),                       # 完整端口扫描 (1-10000)
        'all': []  # 将在初始化时合并所有端口
    }

    # 端口服务映射
    PORT_MAP = {
        21: 'FTP',
        22: 'SSH',
        80: 'HTTP',
        81: 'HTTP',
        135: 'RPC',
        139: 'NetBIOS',
        443: 'HTTPS',
        445: 'SMB',
        1433: 'MSSQL',
        1521: 'Oracle',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        6379: 'Redis',
        7001: 'WebLogic',
        8000: 'HTTP',
        8080: 'HTTP-Proxy',
        8089: 'HTTP',
        9000: 'HTTP',
        9200: 'Elasticsearch',
        11211: 'Memcached',
        27017: 'MongoDB'
    }

    def __init__(self, threads: int = 10):
        self.threads = threads
        self.logger = logging.getLogger("IPScanner")
        self.total_ips = 0
        self.scanned_ips = 0
        self.results = defaultdict(set)
        self._lock = threading.Lock()
        self._print_lock = threading.Lock()
        self._progress_thread = None
        self._scanning = False
        
        # 合并所有常用端口到 'all' 类型（不包括 'full' 范围）
        all_ports = set()
        for port_type, port_list in self.DEFAULT_PORTS.items():
            if port_type not in ['all', 'full']:
                all_ports.update(port_list)
        self.DEFAULT_PORTS['all'] = sorted(list(all_ports))

    def get_ports(self, port_type: str = 'web') -> List[int]:
        """获取指定类型的端口列表"""
        return self.DEFAULT_PORTS.get(port_type, self.DEFAULT_PORTS['web'])

    def get_service_name(self, port: int) -> str:
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
            123: 'NTP',
            139: 'NetBIOS',
            143: 'IMAP',
            161: 'SNMP',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            500: 'IKE',
            513: 'RLogin',
            873: 'Rsync',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            6379: 'Redis',
            7001: 'WebLogic',
            8009: 'AJP',
            8080: 'HTTP-Proxy',
            8161: 'ActiveMQ',
            8443: 'HTTPS-Alt',
            8888: 'HTTP-Alt',
            9000: 'FastCGI',
            9001: 'Supervisor',
            9043: 'WebSphere',
            9060: 'WebSphere-Admin',
            9080: 'WebSphere-HTTP',
            9090: 'WebLogic-Admin',
            27017: 'MongoDB'
        }
        return f"({common_ports.get(port, 'Unknown')})"

    def parse_ip_input(self, ip_input: str) -> Generator[str, None, None]:
        try:
            if ip_input.startswith('@'):
                with open(ip_input[1:], 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            yield from self.parse_ip_input(line)
            elif '/' in ip_input:
                network = ipaddress.ip_network(ip_input, strict=False)
                for ip in network.hosts():
                    yield str(ip)
            elif '-' in ip_input:
                start_ip, end_ip = ip_input.split('-')
                start = ipaddress.ip_address(start_ip)
                end = ipaddress.ip_address(end_ip)
                current = start
                while current <= end:
                    yield str(current)
                    current += 1
            else:
                yield ip_input
        except Exception as e:
            self.logger.error(f"Error parsing IP input {ip_input}: {str(e)}")

    def check_port(self, ip: str, port: int, timeout: float = 1.0) -> tuple[bool, float]:
        """检查端口是否开放，返回(是否开放, 响应时间)"""
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((ip, port))
                response_time = time.time() - start_time
                return result == 0, response_time
        except Exception:
            return False, time.time() - start_time

    def print_status(self, message: str, end='\n'):
        """线程安全的打印函数"""
        with self._print_lock:
            sys.stdout.write('\r' + ' ' * 80 + '\r')  # 清除当前行
            sys.stdout.write(message + end)
            sys.stdout.flush()

    def update_progress(self):
        """更新进度的线程函数"""
        while self._scanning:
            with self._lock:
                progress = (self.scanned_ips / self.total_ips) * 100
                self.print_status(
                    f"{Fore.BLUE}[*] Progress: {self.scanned_ips}/{self.total_ips} ({progress:.1f}%){Style.RESET_ALL}",
                    end='\r'
                )
            time.sleep(0.5)  # 每0.5秒更新一次进度

    def scan_port(self, ip: str, port: int) -> bool:
        """扫描单个端口"""
        if self.check_port(ip, port):
            with self._lock:
                self.results[ip].add(port)
            service = self.get_service_name(port)
            self.print_status(f"{Fore.GREEN}[+] {ip}:{port} {service}{Style.RESET_ALL}")
            return True
        return False

    def scan_ip(self, ip: str, ports: List[int]) -> None:
        """扫描单个IP的所有端口"""
        try:
            # 创建该IP的线程池
            with ThreadPoolExecutor(max_workers=min(len(ports), 50)) as executor:
                # 为每个端口创建一个任务
                futures = [executor.submit(self.scan_port, ip, port) for port in ports]
                # 等待所有端口扫描完成
                concurrent.futures.wait(futures)
        finally:
            with self._lock:
                self.scanned_ips += 1

    def ping(self, ip: str, timeout: float = 1.0) -> bool:
        """
        使用ICMP检测主机是否存活
        """
        try:
            # Windows系统
            if platform.system().lower() == 'windows':
                # 使用ping命令，-n 1表示发送1个包，-w表示超时时间(毫秒)
                cmd = f'ping -n 1 -w {int(timeout*1000)} {ip}'
                return subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
            # Linux/Mac系统
            else:
                # 使用ping命令，-c 1表示发送1个包，-W表示超时时间(秒)
                cmd = f'ping -c 1 -W {int(timeout)} {ip}'
                return subprocess.call(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except:
            return False

    def discover_hosts(self, ip_list: List[str], threads: int = 100) -> Set[str]:
        """使用ICMP探测存活主机"""
        alive_hosts = set()
        total_hosts = len(ip_list)
        scanned_hosts = 0

        print(f"\n{Fore.YELLOW}[*] Starting host discovery for {total_hosts} targets...{Style.RESET_ALL}\n")

        def _scan_host(ip: str):
            nonlocal scanned_hosts
            try:
                if self.ping(ip):
                    with self._lock:
                        alive_hosts.add(ip)
                        self.print_status(f"{Fore.GREEN}[+] {ip} is alive{Style.RESET_ALL}")
            finally:
                with self._lock:
                    nonlocal scanned_hosts
                    scanned_hosts += 1
                    progress = (scanned_hosts / total_hosts) * 100
                    self.print_status(
                        f"{Fore.BLUE}[*] Progress: {scanned_hosts}/{total_hosts} ({progress:.1f}%){Style.RESET_ALL}",
                        end='\r'
                    )

        # 为每个IP创建一个线程进行存活探测
        with ThreadPoolExecutor(max_workers=threads) as executor:
            list(executor.map(_scan_host, ip_list))

        print(f"\n{Fore.BLUE}[*] Host discovery completed. Found {len(alive_hosts)} alive hosts.{Style.RESET_ALL}\n")
        return alive_hosts

    def scan(self, targets: Union[str, List[str]], ports: List[int] = None, port_type: str = 'web') -> dict:
        """执行扫描"""
        self.results.clear()
        self.scanned_ips = 0
        ip_list = []

        if ports is None:
            ports = self.get_ports(port_type)

        if isinstance(targets, str):
            targets = [targets]

        for target in targets:
            ip_list.extend(list(self.parse_ip_input(target)))

        # 首先进行主机发现
        alive_hosts = self.discover_hosts(ip_list)
        if not alive_hosts:
            print(f"{Fore.RED}[!] No alive hosts found.{Style.RESET_ALL}")
            return {}

        self.total_ips = len(alive_hosts)
        print(f"\n{Fore.YELLOW}[*] Starting port scan of {self.total_ips} alive hosts ({len(ports)} ports){Style.RESET_ALL}\n")

        try:
            # 为每个IP创建一个线程
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # 提交所有IP的扫描任务
                futures = []
                for ip in alive_hosts:
                    futures.append(executor.submit(self.scan_ip, ip, ports))

                # 等待所有IP扫描完成
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()  # 获取结果，处理可能的异常
                    except Exception as e:
                        self.logger.error(f"Error scanning IP: {str(e)}")

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")

        print(f"\n{Fore.BLUE}[*] Port scan completed.{Style.RESET_ALL}\n")
        return dict(self.results) 