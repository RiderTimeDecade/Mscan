from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Dict
from .poc import BasePOC
import logging
from colorama import Fore, Style

class Scanner:
    def __init__(self, threads: int = 10):
        self.threads = threads
        self.pocs: List[BasePOC] = []
        self.logger = logging.getLogger("Scanner")

    def register_poc(self, poc: BasePOC) -> None:
        """注册POC"""
        self.pocs.append(poc)
        self.logger.debug(f"Registered POC: {poc.name}")

    def register_pocs(self, pocs: List[BasePOC]) -> None:
        """批量注册POC"""
        for poc in pocs:
            self.register_poc(poc)

    def scan_single_poc(self, target: str, poc: BasePOC) -> Optional[dict]:
        """使用单个POC扫描目标"""
        try:
            result = poc.verify(target)
            if result:
                self.logger.info(f"Found vulnerability: {poc.name} in {target}")
                return {
                    "poc_name": poc.name,
                    "target": target,
                    "result": result
                }
        except Exception as e:
            self.logger.error(f"Error in POC {poc.name}: {str(e)}")
        return None

    def scan(self, target: str) -> List[Dict]:
        """执行漏洞扫描"""
        results = []
        print(f"\n{Fore.YELLOW}[*] Starting vulnerability scan for {target}...{Style.RESET_ALL}\n")

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [
                    executor.submit(self.scan_single_poc, target, poc)
                    for poc in self.pocs
                ]
                
                for future in futures:
                    try:
                        result = future.result()
                        if result:
                            results.append(result)
                    except Exception as e:
                        self.logger.error(f"Scan error: {str(e)}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")

        print(f"\n{Fore.BLUE}[*] Vulnerability scan completed.{Style.RESET_ALL}\n")
        return results 