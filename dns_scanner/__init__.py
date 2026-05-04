"""
DNS Scanner Package
Advanced Asynchronous DNS Scanner for finding working DNS resolvers.

Author: Mojtaba Akhbari
"""

from .core import DNSScanner, ScanState
from .ip_generator import IPGenerator
from .ui import UIManager
from .config import LEAKED_SUBNETS, CUSTOM_FIRST_OCTETS, CUSTOM_FIRST_AND_SECOND_OCTETS

__version__ = "1.0.0"
__all__ = [
    "DNSScanner",
    "ScanState",
    "IPGenerator",
    "UIManager",
    "LEAKED_SUBNETS",
    "CUSTOM_FIRST_OCTETS",
    "CUSTOM_FIRST_AND_SECOND_OCTETS",
]
