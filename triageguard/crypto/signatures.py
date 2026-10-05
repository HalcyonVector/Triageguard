"""Byte signatures used to identify ciphers in memory and binaries.

Each signature has a weight between 0 and 1. Confidence for an algorithm is
1 - prod(1 - w) over the distinct signatures that matched, so one strong hit
counts a lot and several weak hits add up without ever reaching 100%.

Strings are searched as both ASCII and UTF-16LE (Windows APIs use wide strings).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Sig:
    algo: str
    name: str
    pattern: bytes
    weight: float
    kind: str = "constant"  # constant | api | string
    wide: bool = False  # also search UTF-16LE form


def _h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


def _api(algo, name, weight, kind="api"):
    return Sig(algo, name, name.encode(), weight, kind, wide=True)


SIGNATURES = [
    # ---------------- AES ----------------
    Sig("AES", "AES S-box", _h("637c777bf26b6fc53001672bfed7ab76"), 0.6),
    Sig("AES", "AES inverse S-box", _h("52096ad53036a538bf40a39e81f3d7fb"), 0.5),
    Sig("AES", "AES Te0 table (LE)", _h("a56363c6847c7cf8997777ee8d7b7bf6"), 0.6),
    Sig("AES", "AES Te0 table (BE)", _h("c66363a5f87c7c84ee777799f67b7b8d"), 0.6),
    Sig("AES", "AES Rcon (dword)", _h("01000000020000000400000008000000100000002000000040000000800000001b000000"), 0.2),
    _api("AES", "CALG_AES", 0.3),
    _api("AES", "AES-256", 0.25, "string"),
    _api("AES", "Microsoft Enhanced RSA and AES Cryptographic Provider", 0.3),
    Sig("AES", "BCRYPT_AES_ALGORITHM", "AES".encode("utf-16le") + b"\x00\x00", 0.1, "api"),
    # ---------------- DES / 3DES ----------------
    Sig("DES", "DES initial permutation table", _h("3a322a221a120a023c342c241c140c04"), 0.5),
    Sig("DES", "DES PC-1 table", _h("39312921191109013a322a221a120a02"), 0.5),
    Sig("DES", "DES S1 box", _h("0e040d01020f0b08030a060c05090007"), 0.5),
    Sig("DES", "DES SPtrans table (OpenSSL)", _h("000808020000080002000002"), 0.6),
    _api("DES", "CALG_DES", 0.3),
    _api("3DES", "CALG_3DES", 0.5),
    _api("3DES", "DES-EDE3", 0.5, "string"),
    Sig("3DES", "BCRYPT_3DES_ALGORITHM", "3DES".encode("utf-16le") + b"\x00\x00", 0.5, "api"),
    # ---------------- ChaCha20 / Salsa20 ----------------
    Sig("ChaCha20/Salsa20", "sigma 'expand 32-byte k'", b"expand 32-byte k", 0.75),
    Sig("ChaCha20/Salsa20", "tau 'expand 16-byte k'", b"expand 16-byte k", 0.4),
    _api("ChaCha20/Salsa20", "chacha20", 0.4, "string"),
    _api("ChaCha20/Salsa20", "salsa20", 0.4, "string"),
    _api("ChaCha20/Salsa20", "xchacha20", 0.3, "string"),
    # ---------------- AES-GCM ----------------
    Sig("AES-GCM", "GHASH rem_8bit table", _h("0000c201 84034602 0807ca06 8c044e05"), 0.6),
    Sig("AES-GCM", "GHASH rem_4bit table (64-bit)", _h("0000000000000000000000000000201c00000000000040380000000000006024"), 0.6),
    _api("AES-GCM", "ChainingModeGCM", 0.7),
    _api("AES-GCM", "aes-256-gcm", 0.5, "string"),
    _api("AES-GCM", "aes-128-gcm", 0.5, "string"),
    _api("AES-GCM", "AES-GCM", 0.4, "string"),
    # ---------------- ECC ----------------
    Sig("Curve25519", "p = 2^255-19 (LE)", b"\xed" + b"\xff" * 30 + b"\x7f", 0.6),
    Sig("Curve25519", "Ed25519 d constant (LE)", _h("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352"), 0.7),
    _api("Curve25519", "curve25519", 0.4, "string"),
    _api("Curve25519", "x25519", 0.4, "string"),
    _api("Curve25519", "ed25519", 0.4, "string"),
    Sig("ECC P-256", "P-256 b (BE)", _h("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"), 0.7),
    Sig("ECC P-256", "P-256 b (LE)", _h("4b60d2273e3cce3bf6b053ccb0061d65bc86987655bdebb3e7933aaad835c65a"), 0.7),
    Sig("ECC P-256", "P-256 order n (BE)", _h("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"), 0.6),
    Sig("ECC P-256", "P-256 Gx (BE)", _h("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"), 0.6),
    _api("ECC P-256", "ECDH_P256", 0.5),
    _api("ECC P-256", "ECDSA_P256", 0.5),
    _api("ECC P-256", "prime256v1", 0.4, "string"),
    Sig("ECC secp256k1", "secp256k1 order n (BE)", _h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), 0.7),
    Sig("ECC secp256k1", "secp256k1 p (BE)", _h("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"), 0.6),
    _api("ECC secp256k1", "secp256k1", 0.4, "string"),
    # ---------------- RSA ----------------
    Sig("RSA", "rsaEncryption OID", _h("06092a864886f70d010101"), 0.5),
    Sig("RSA", "CAPI PUBLICKEYBLOB header", _h("0602000000a40000 52534131"), 0.7),
    Sig("RSA", "CAPI PRIVATEKEYBLOB header", _h("0702000000a40000 52534132"), 0.7),
    Sig("RSA", "PEM RSA private key", b"-----BEGIN RSA PRIVATE KEY-----", 0.7, "string"),
    Sig("RSA", "PEM public key", b"-----BEGIN PUBLIC KEY-----", 0.4, "string"),
    _api("RSA", "CryptImportKey", 0.2),
    _api("RSA", "RSAPUBLICBLOB", 0.5),
    _api("RSA", "BCRYPT_RSA_ALGORITHM", 0.3),
    # ---------------- Generic crypto API usage (no algo) ----------------
    _api("generic", "CryptEncrypt", 0.3),
    _api("generic", "BCryptEncrypt", 0.3),
    _api("generic", "CryptGenKey", 0.3),
    _api("generic", "CryptAcquireContext", 0.3),
    _api("generic", "BCryptGenerateSymmetricKey", 0.3),
]
