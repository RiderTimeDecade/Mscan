import requests
import urllib3
from typing import Optional, Dict, Any
import logging

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HTTPClient:
    def __init__(self):
        self.session = requests.Session()
        self.logger = logging.getLogger("HTTPClient")
        
    def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> Optional[requests.Response]:
        """发送HTTP请求"""
        try:
            kwargs.setdefault('verify', False)
            kwargs.setdefault('timeout', 10)
            response = self.session.request(method, url, **kwargs)
            return response
        except Exception as e:
            self.logger.error(f"Request error: {str(e)}")
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('GET', url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request('POST', url, **kwargs) 