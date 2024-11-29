from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import requests
from lib.http import HTTPClient

class BasePOC(ABC):
    def __init__(self):
        self.name: str = self.__class__.__name__
        self.description: str = ""
        self.reference: str = ""
        self.type: str = ""
        self.http = HTTPClient()

    @abstractmethod
    def verify(self, target: str) -> Optional[Dict[str, Any]]:
        """验证目标是否存在漏洞"""
        pass

    @abstractmethod
    def exploit(self, target: str) -> Optional[Dict[str, Any]]:
        """利用漏洞获取更多信息"""
        pass 