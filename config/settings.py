# 扫描器配置
THREADS = 500
TIMEOUT = 3
MAX_RETRIES = 3

# HTTP配置
USER_AGENT = "VulScanner/1.0"
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close"
}

# 日志配置
LOG_LEVEL = "INFO"
LOG_FILE = "vulscanner.log"

# 默认端口配置
DEFAULT_PORTS = {
    'common': '21,22,23,25,53,80,110,139,143,443,445,465,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017',
    'minimal': '80,443,8080',
    'full': ','.join(map(str, range(1, 65536)))
}

# 扫描模式说明
PORT_MODE_DESC = {
    'common': '常见服务端口',
    'web': 'Web服务端口',
    'db': '数据库端口',
    'remote': '远程服务端口',
    'mail': '邮件服务端口',
    'full': '完整端口扫描(1-65536)'
}

# 端口服务映射
PORT_MAP = {
    20: 'FTP-DATA',
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    81: 'HTTP',
    88: 'Kerberos',
    110: 'POP3',
    111: 'RPC',
    123: 'NTP',
    135: 'RPC',
    139: 'NetBIOS',
    143: 'IMAP',
    161: 'SNMP',
    389: 'LDAP',
    443: 'HTTPS',
    445: 'SMB',
    465: 'SMTPS',
    500: 'IKE',
    512: 'rexec',
    513: 'rlogin',
    514: 'syslog',
    515: 'LPD',
    520: 'RIP',
    523: 'IBM-DB2',
    548: 'AFP',
    623: 'IPMI',
    626: 'serialnumberd',
    636: 'LDAPS',
    873: 'rsync',
    902: 'VMware',
    1080: 'SOCKS',
    1099: 'RMI',
    1433: 'MSSQL',
    1434: 'MSSQL-UDP',
    1521: 'Oracle',
    1158: 'Oracle-EMCTL',
    2082: 'cPanel',
    2083: 'cPanel-SSL',
    2181: 'ZooKeeper',
    2222: 'SSH',
    2375: 'Docker',
    2601: 'zebra',
    2604: 'zebra',
    3128: 'Squid',
    3306: 'MySQL',
    3312: 'Kangle',
    3389: 'RDP',
    3690: 'SVN',
    4440: 'Rundeck',
    4848: 'GlassFish',
    5432: 'PostgreSQL',
    5632: 'PCAnywhere',
    5900: 'VNC',
    5984: 'CouchDB',
    6379: 'Redis',
    7001: 'WebLogic',
    7002: 'WebLogic',
    8000: 'HTTP',
    8080: 'HTTP-Proxy',
    8089: 'HTTP',
    8443: 'HTTPS',
    8888: 'HTTP',
    9000: 'HTTP',
    9001: 'HTTP',
    9090: 'HTTP',
    9200: 'Elasticsearch',
    9300: 'Elasticsearch',
    10000: 'Webmin',
    11211: 'Memcached',
    27017: 'MongoDB',
    27018: 'MongoDB',
    50000: 'DB2'
}

# SSH爆破配置
DEFAULT_SSH_USER_FILE = 'data/users.txt'
DEFAULT_SSH_PASS_FILE = 'data/passwords.txt'

# FTP爆破配置
DEFAULT_FTP_USER_FILE = 'data/ftp_users.txt'
DEFAULT_FTP_PASS_FILE = 'data/ftp_passwords.txt' 