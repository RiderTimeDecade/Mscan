import requests
import re
import hashlib
import json
import sqlite3
import os
from typing import Dict, Optional, List, Set
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style
import threading
import urllib3
from bs4 import BeautifulSoup
import time
import random
import sys
import concurrent.futures
from lib.utils.http_utils import HTTPClient

# 禁用 SSL 警告
urllib3.disable_warnings()

class CMSScanner:
    def __init__(self):
        self.print_lock = threading.Lock()
        self.http_client = HTTPClient()
        self._lock = threading.Lock()
        self.total_urls = 0
        self.scanned_urls = 0
        
        # 优化会话配置
        self.http_client.session.verify = False
        self.http_client.session.timeout = 3  # 全局超时设置
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=100,    # 连接池大小
            pool_maxsize=100,       # 最大连接数
            max_retries=0,          # 禁用重试
            pool_block=False        # 非阻塞
        )
        self.http_client.session.mount('http://', adapter)
        self.http_client.session.mount('https://', adapter)
        
        # 加载 TideFinger 数据库
        self.db_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'data', 'cms_finger.db')
        self.load_tide_finger()

    def get_response(self, url: str, max_redirects: int = 3) -> Optional[requests.Response]:
        """优化的HTTP请求，支持跟踪跳转"""
        try:
            headers = {
                'User-Agent': self.get_random_ua(),
                'Accept': '*/*',
                'Connection': 'keep-alive'
            }
            
            # 手动处理重定向
            response = self.http_client.session.get(
                url, 
                headers=headers, 
                timeout=1,  # 1秒超时
                verify=False,
                allow_redirects=False
            )
            
            # 如果是重定向响应，跟踪跳转
            redirect_count = 0
            while response.is_redirect and redirect_count < max_redirects:
                redirect_url = response.headers.get('Location')
                if not redirect_url:
                    break
                    
                # 处理相对URL
                if redirect_url.startswith('/'):
                    redirect_url = f"{'/'.join(url.split('/')[:3])}{redirect_url}"
                elif not redirect_url.startswith(('http://', 'https://')):
                    redirect_url = f"{url.rstrip('/')}/{redirect_url.lstrip('/')}"
                
                response = self.http_client.session.get(
                    redirect_url,
                    headers=headers,
                    timeout=1,
                    verify=False,
                    allow_redirects=False
                )
                redirect_count += 1
            
            return response
            
        except (requests.Timeout, requests.RequestException):
            return None

    def scan(self, ip_ports: Dict[str, set]) -> Dict[str, Dict]:
        """优化的扫描流程"""
        results = {}
        self.total_urls = sum(len(ports) for ports in ip_ports.values())
        
        print(f"\n{Fore.YELLOW}[*] Starting web scan for {self.total_urls} targets...{Style.RESET_ALL}\n")

        try:
            tasks = []
            for ip, ports in ip_ports.items():
                for port in ports:
                    url = f"http://{ip}:{port}" if port != 443 else f"https://{ip}"
                    tasks.append((url, ip, port))

            # 使用信号量限制并发数
            semaphore = threading.Semaphore(20)
            
            def scan_with_semaphore(task):
                url, ip, port = task
                try:
                    with semaphore:
                        return self.check_cms(url, ip, port)
                except Exception:
                    return None

            # 使用线程池执行任务
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for task in tasks:
                    futures.append(executor.submit(scan_with_semaphore, task))

                # 处理完成的任务
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if result and result['status_code'] > 0:
                            key = f"{result['ip']}:{result['port']}"
                            results[key] = result
                    except Exception:
                        pass

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Web scan interrupted by user{Style.RESET_ALL}")

        print(f"\n{Fore.BLUE}[*] Web scan completed. Scanned {len(results)} targets.{Style.RESET_ALL}\n")
        return results

    def identify_technologies(self, response, content: str) -> Set[str]:
        """识别网站使用的技术"""
        technologies = set()
        headers = response.headers
        
        # 服务器类型
        if 'Server' in headers:
            server = headers['Server'].lower()
            if 'nginx' in server:
                technologies.add('Nginx')
            if 'apache' in server:
                technologies.add('Apache')
            if 'iis' in server:
                technologies.add('IIS')
            if 'tomcat' in server:
                technologies.add('Tomcat')
            if 'jetty' in server:
                technologies.add('Jetty')

        # 编程语言
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By'].lower()
            if 'php' in powered_by:
                technologies.add('PHP')
            if 'asp.net' in powered_by:
                technologies.add('ASP.NET')
            if 'jsp' in powered_by:
                technologies.add('JSP')
            if 'servlet' in powered_by:
                technologies.add('Java Servlet')

        # 从内容中识别技术
        content_lower = content.lower()
        if 'php' in content_lower or '.php' in content_lower:
            technologies.add('PHP')
        if 'asp.net' in content_lower or '.aspx' in content_lower:
            technologies.add('ASP.NET')
        if 'jsp' in content_lower or '.jsp' in content_lower:
            technologies.add('JSP')
        if 'laravel' in content_lower:
            technologies.add('Laravel')
        if 'django' in content_lower:
            technologies.add('Django')
        if 'spring' in content_lower:
            technologies.add('Spring')
        if 'struts' in content_lower:
            technologies.add('Struts')

        # 前端框架
        if 'vue' in content_lower:
            technologies.add('Vue.js')
        if 'react' in content_lower:
            technologies.add('React')
        if 'angular' in content_lower:
            technologies.add('Angular')
        if 'jquery' in content_lower:
            technologies.add('jQuery')
        if 'bootstrap' in content_lower:
            technologies.add('Bootstrap')

        # 数据库
        if 'mysql' in content_lower:
            technologies.add('MySQL')
        if 'postgresql' in content_lower:
            technologies.add('PostgreSQL')
        if 'oracle' in content_lower:
            technologies.add('Oracle')
        if 'mongodb' in content_lower:
            technologies.add('MongoDB')

        # Web服务器特征
        if 'phpmyadmin' in content_lower:
            technologies.add('phpMyAdmin')
        if 'weblogic' in content_lower:
            technologies.add('WebLogic')
        if 'websphere' in content_lower:
            technologies.add('WebSphere')
        if 'jboss' in content_lower:
            technologies.add('JBoss')

        return technologies

    def decode_content(self, response: requests.Response) -> str:
        """智能解码响应内容"""
        # 尝试从Content-Type获取编码
        content_type = response.headers.get('content-type', '').lower()
        if 'charset=' in content_type:
            try:
                charset = content_type.split('charset=')[-1].split(';')[0].strip()
                return response.content.decode(charset, errors='replace')
            except:
                pass

        # 尝试使用apparent_encoding
        try:
            return response.content.decode(response.apparent_encoding, errors='replace')
        except:
            pass

        # 尝试常见编码
        encodings = ['utf-8', 'gbk', 'gb2312', 'big5', 'utf-16', 'ascii']
        for encoding in encodings:
            try:
                return response.content.decode(encoding, errors='replace')
            except:
                continue

        # 如果都失败了，使用replace错误处理
        return response.content.decode('utf-8', errors='replace')

    def check_cms(self, url: str, ip: str, port: int) -> Dict:
        """优化的CMS检测，超时快速跳过"""
        result = {
            'ip': ip,
            'port': port,
            'url': url,
            'cms': 'Unknown',
            'server': 'Unknown',
            'technologies': set(),
            'title': '',
            'status_code': 0,
            'content_length': 0,
            'redirect_url': None
        }

        try:
            response = self.get_response(url)
            if not response:
                return result

            # 智能解码响应内容
            content = self.decode_content(response)

            # 获取基本信息
            result['status_code'] = response.status_code
            result['content_length'] = len(response.content)
            result['server'] = response.headers.get('Server', 'Unknown')
            
            result['title'] = self.extract_title(content)

            # 识别技术栈
            result['technologies'] = self.identify_technologies(response, content)

            # CMS识别
            headers = str(response.headers)
            for cms_name, rule in self.tide_fingers.items():
                if self.handle_tide_rule(rule, headers, content, result['title']):
                    result['cms'] = cms_name
                    break

            # 构建URL显示
            url_display = f"{'https' if port == 443 else 'http'}://{ip}"
            if port not in [80, 443]:
                url_display += f":{port}"

            # 输出结果
            output = f"{Fore.GREEN}[*] WebTitle {url_display:<30} "
            output += f"code:{result['status_code']} "
            output += f"len:{result['content_length']:<8} "
            
            # 确保标题不是乱码
            title = result['title']
            if not title or title == 'None':
                title = 'Web Page'
            else:
                # 如果标题看起来是乱码，尝试重新解码
                if any(ord(c) > 0xFFFF for c in title):
                    try:
                        title = title.encode('iso-8859-1').decode('utf-8')
                    except:
                        try:
                            title = title.encode('raw_unicode_escape').decode('utf-8')
                        except:
                            title = 'Web Page'
            
            output += f"title:{title}"

            # 添加服务器信息
            if result['server'] != 'Unknown':
                output += f" [{result['server']}]"

            # 添加技术栈信息
            if result['technologies']:
                output += f" [{', '.join(result['technologies'])}]"

            # 添加CMS信息
            if result['cms'] != 'Unknown':
                output += f" [{result['cms']}]"
            
            output += Style.RESET_ALL
            self.print_status(output)

        except Exception:
            pass

        return result

    def load_tide_finger(self):
        """加载 TideFinger 指纹库"""
        self.tide_fingers = {}
        try:
            if os.path.exists(self.db_path):
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT name, keys FROM tide')
                    for row in cursor.fetchall():
                        self.tide_fingers[row[0]] = row[1]
            else:
                print(f"{Fore.YELLOW}[!] TideFinger database not found at {self.db_path}, creating...{Style.RESET_ALL}")
                self.create_cms_finger_db()
        except Exception as e:
            print(f"{Fore.RED}[-] Error loading TideFinger database: {str(e)}{Style.RESET_ALL}")
            self.tide_fingers = {}

    def create_cms_finger_db(self):
        """创建 CMS 指纹数据库"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS tide (
            name TEXT PRIMARY KEY,
            keys TEXT
        )
        ''')
        
        # 添加基本的指纹
        basic_fingers = [
            ('Apache Tomcat', 'title="Apache Tomcat"||body="Apache Tomcat"'),
            ('Nginx', 'header="nginx"'),
            ('IIS', 'header="IIS"'),
            ('WordPress', 'body="wp-content"||body="wp-includes"'),
            ('Joomla', 'body="joomla"||body="/components/com_"'),
            ('Drupal', 'body="Drupal"||body="drupal"'),
            ('phpMyAdmin', 'title="phpMyAdmin"||body="phpMyAdmin"'),
            ('WebLogic', 'title="WebLogic"||body="WebLogic"'),
            ('WebSphere', 'title="WebSphere"||body="WebSphere"'),
            ('JBoss', 'title="JBoss"||body="JBoss"'),
            ('Jenkins', 'title="Jenkins"||body="Jenkins"'),
            ('Tomcat', 'title="Tomcat"||body="Tomcat"'),
            ('Spring', 'body="spring"'),
            ('Laravel', 'body="laravel"'),
            ('ThinkPHP', 'body="thinkphp"'),
            ('Django', 'body="django"'),
            ('ASP.NET', 'body="asp.net"||header="ASP.NET"'),
            ('PHP', 'header="PHP"||body="php"'),
            ('JSP', 'body=".jsp"'),
            ('H3C Router', 'title="Web user login"||body="h3c"'),
            ('D-Link Router', 'title="D-Link"||body="dlink"'),
            ('TP-Link Router', 'title="TL-"||body="tplink"'),
            ('Cisco Router', 'title="Cisco"||body="cisco"'),
        ]
        
        cursor.executemany('INSERT OR REPLACE INTO tide (name, keys) VALUES (?, ?)', basic_fingers)
        conn.commit()
        conn.close()

    def get_random_ua(self):
        """获取随机User-Agent"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/91.0.864.59'
        ]
        return random.choice(user_agents)

    def check_rule(self, key: str, header: str, body: str, title: str) -> bool:
        """TideFinger 规则匹配"""
        try:
            if 'title="' in key:
                if re.findall(r'title="(.*)"', key)[0].lower() in title.lower():
                    return True
            elif 'body="' in key:
                if re.findall(r'body="(.*)"', key)[0] in body:
                    return True
            elif 'header="' in key:
                if re.findall(r'header="(.*)"', key)[0] in header:
                    return True
            return False
        except:
            return False

    def handle_tide_rule(self, key: str, header: str, body: str, title: str) -> bool:
        """处理 TideFinger 复杂规则"""
        if '||' in key and '&&' not in key and '(' not in key:
            return any(self.check_rule(rule, header, body, title) for rule in key.split('||'))
        elif '&&' in key and '||' not in key and '(' not in key:
            return all(self.check_rule(rule, header, body, title) for rule in key.split('&&'))
        elif '||' not in key and '&&' not in key and '(' not in key:
            return self.check_rule(key, header, body, title)
        return False

    def print_status(self, message: str, end='\n'):
        """线程安全的打印函数"""
        with self.print_lock:
            sys.stdout.write('\r' + ' ' * 100 + '\r')  # 清除当前行
            sys.stdout.write(message + end)
            sys.stdout.flush()

    def extract_title(self, content: str) -> str:
        """提取页面标题，优先获取主标题"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # 1. 首先尝试获取 title 标签内容
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
                if title and title.lower() != 'none':
                    # 处理常见的标题分隔符
                    for separator in [' - ', ' | ', ' :: ', ' » ', ' > ', ' / ']:
                        if separator in title:
                            # 取第一部分作为主标题
                            title = title.split(separator)[0].strip()
                    return title
            
            # 2. 尝试获取 h1 标签内容
            h1_tags = soup.find_all('h1', limit=1)
            if h1_tags:
                h1_text = h1_tags[0].get_text().strip()
                if h1_text and h1_text.lower() != 'none':
                    return h1_text
            
            # 3. 尝试获取页面主要内容区域的标题
            main_content = soup.find(['main', 'article', 'div'], class_=lambda x: x and any(word in x.lower() for word in ['main', 'content', 'article']))
            if main_content:
                # 查找主要内容区域中的第一个标题
                main_title = main_content.find(['h1', 'h2', 'h3'])
                if main_title and main_title.string:
                    return main_title.string.strip()
            
            # 4. 如果找不到标题，返回 Web Page
            return 'Web Page'
            
        except Exception:
            return 'Web Page'

    # ... (其他方法保持不变)