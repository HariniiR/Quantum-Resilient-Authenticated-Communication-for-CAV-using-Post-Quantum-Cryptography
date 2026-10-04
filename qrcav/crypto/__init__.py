"""Cryptographic building blocks: suites, KDF, record layer."""

from .kdf import H, SessionKeys, derive_session_keys, hkdf_expand, hkdf_extract
from .records import (
    FIRST_DATA_CTR,
    RECORD_OVERHEAD,
    RecordError,
    RecordReceiver,
    RecordSender,
    make_nonce,
)
from .suites import (
    HAVE_OPENSSL_PQC,
    HAVE_PURE_PQC,
    SUITE_DEFS,
    Suite,
    get_suite,
)

__all__ = [
    "H", "SessionKeys", "derive_session_keys", "hkdf_expand", "hkdf_extract",
    "FIRST_DATA_CTR", "RECORD_OVERHEAD", "RecordError", "RecordReceiver",
    "RecordSender", "make_nonce", "HAVE_OPENSSL_PQC", "HAVE_PURE_PQC",
    "SUITE_DEFS", "Suite", "get_suite",
]
