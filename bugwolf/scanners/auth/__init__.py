"""Auth scanners — Phase 1.5 + 2.1."""

from bugwolf.scanners.auth.jwt import JWTScanner
from bugwolf.scanners.auth.jwt_alg_confusion import JWTAlgConfusionScanner
from bugwolf.scanners.auth.jwt_key_injection import JWTKeyInjectionScanner
from bugwolf.scanners.auth.oauth import OAuthScanner
from bugwolf.scanners.auth.saml import SAMLScanner
from bugwolf.scanners.auth.saml_xsw import SAMLXSWScanner
from bugwolf.scanners.auth.session import SessionScanner

__all__ = [
    "JWTScanner",
    "JWTAlgConfusionScanner",
    "JWTKeyInjectionScanner",
    "OAuthScanner",
    "SAMLScanner",
    "SAMLXSWScanner",
    "SessionScanner",
]