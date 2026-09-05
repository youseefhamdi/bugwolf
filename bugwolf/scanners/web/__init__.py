"""Web scanners — Phase 1.5 + 2.1."""

from bugwolf.scanners.web.ato_chain import ATOChainScanner
from bugwolf.scanners.web.brute_force import BruteForceScanner
from bugwolf.scanners.web.cache_poisoning import CachePoisoningScanner
from bugwolf.scanners.web.captcha_bypass import CaptchaBypassScanner
from bugwolf.scanners.web.clickjacking import ClickjackingScanner
from bugwolf.scanners.web.cors import CORSScanner
from bugwolf.scanners.web.crlf import CRLFScanner
from bugwolf.scanners.web.csrf import CSRFScanner
from bugwolf.scanners.web.dom_xss import DOMXSSScanner
from bugwolf.scanners.web.file_upload import FileUploadScanner
from bugwolf.scanners.web.grpc import GRPCScanner
from bugwolf.scanners.web.host_header import HostHeaderScanner
from bugwolf.scanners.web.http_smuggling import HTTPSmugglingScanner
from bugwolf.scanners.web.idor import IDORScanner
from bugwolf.scanners.web.lfi_rfi import LFIRFIScanner
from bugwolf.scanners.web.mfa_bypass import MFABypassScanner
from bugwolf.scanners.web.open_redirect import OpenRedirectScanner
from bugwolf.scanners.web.password_reset import PasswordResetScanner
from bugwolf.scanners.web.race_condition import RaceConditionScanner
from bugwolf.scanners.web.rag_vector import RAGVectorScanner
from bugwolf.scanners.web.shadow_api import ShadowAPIScanner
from bugwolf.scanners.web.spa_api import SPAAPIScanner
from bugwolf.scanners.web.sqli import SQLiScanner
from bugwolf.scanners.web.ssrf import SSRFScanner
from bugwolf.scanners.web.ssti import SSTIScanner
from bugwolf.scanners.web.websocket import WebSocketScanner
from bugwolf.scanners.web.xss import XSSScanner
from bugwolf.scanners.web.xxe import XXEScanner

__all__ = [
    "ATOChainScanner",
    "BruteForceScanner",
    "CachePoisoningScanner",
    "CaptchaBypassScanner",
    "ClickjackingScanner",
    "CORSScanner",
    "CRLFScanner",
    "CSRFScanner",
    "DOMXSSScanner",
    "FileUploadScanner",
    "GRPCScanner",
    "HostHeaderScanner",
    "HTTPSmugglingScanner",
    "IDORScanner",
    "LFIRFIScanner",
    "MFABypassScanner",
    "OpenRedirectScanner",
    "PasswordResetScanner",
    "RaceConditionScanner",
    "RAGVectorScanner",
    "ShadowAPIScanner",
    "SPAAPIScanner",
    "SQLiScanner",
    "SSRFScanner",
    "SSTIScanner",
    "WebSocketScanner",
    "XSSScanner",
    "XXEScanner",
]