"""PKI tests."""

from nstp.pki import *


def test_verify_server_certificate():
    trust_store = load_trust_store(Path("data/trusted_certs.db"))
    verifier = CertificateVerifier(trust_store)
    server_cert = load_certificate(Path("data/server.crt"))
    verifier.verify_server_certificate(server_cert, "127.0.0.1")


def test_verify_server_certificate_status():
    trust_store = load_trust_store(Path("data/trusted_certs.db"))
    verifier = CertificateVerifier(trust_store)
    server_cert = load_certificate(Path("data/server.crt"))
    status = load_certificate_status(Path("data/status.msg"))
    verifier.verify_server_certificate_status(server_cert, status, "127.0.0.1")


def test_hash_certificate():
    cert = load_certificate(Path("data/client.crt"))
    assert cert is not None
    cert_hash = hash_certificate_sha256(cert)
    assert cert_hash.algorithm == HashAlgorithm.SHA256
    assert cert_hash.value == b'\xd2/&Bh8\x1bh\xdd\xd3\xc3Y7\xfeL\x9ao\x8da\xef\x00\x97\xad|j\xa8\xf2\xb5WI\x8f\xc5'
    cert_hash = hash_certificate_sha512(cert)
    assert cert_hash.algorithm == HashAlgorithm.SHA512
    assert cert_hash.value == b'\xc9h\x8e\x90\xa5\xab0\x90\x9d\x8bpNT\x8b\xf7X\xe6\xb3\xc0\x96\xd1\xbf\xc7dh\x1a\x88\x83#\xe5X\x10\x83?\x80\xf0\xc2\xb7\xae\xe6\x84\x10wEu#\xd8\xa1\x18WK\xf8!YI\xc9\xd9#\xed7\xbc&vV'
