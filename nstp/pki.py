"""PKI interface."""

import datetime
import hashlib
import logging
import struct
from pathlib import Path

from nacl.bindings import \
    crypto_sign_ed25519ph_state, \
    crypto_sign_ed25519ph_update, \
    crypto_sign_ed25519ph_final_verify

from nstp_v4_pb2 import *


def load_trust_store(path: Path) -> CertificateStore:
    """Deserialize a trust store."""

    store = CertificateStore()
    with path.open("rb") as fd:
        data = fd.read()
        store.ParseFromString(data)
    return store


def load_certificate(path: Path) -> Certificate:
    """Deserialize a certificate."""

    cert = Certificate()
    with path.open("rb") as fd:
        data = fd.read()
        cert.ParseFromString(data)
    return cert


def load_private_key(path: Path) -> PrivateKey:
    """Deserialize a private key."""

    key = PrivateKey()
    with path.open("rb") as fd:
        data = fd.read()
        key.ParseFromString(data)
    return key


def load_certificate_status(path: Path) -> CertificateStatusResponse:
    """Deserialize a certificate status response."""

    status = CertificateStatusResponse()
    with path.open("rb") as fd:
        data = fd.read()
        status.ParseFromString(data)
    return status


def hash_certificate_sha256(cert: Certificate) -> CertificateHash:
    h = hashlib.sha256()
    return hash_certificate(cert, h, HashAlgorithm.SHA256)


def hash_certificate_sha512(cert: Certificate) -> CertificateHash:
    h = hashlib.sha512()
    return hash_certificate(cert, h, HashAlgorithm.SHA512)


class CertificateVerifier(object):
    """Certificate verifier."""

    # TODO: Add pinned certs
    def __init__(self, trust_store: CertificateStore) -> None:
        """Initializer."""

        # Hash all trusted certs
        self.trusted_certs = {}
        for c in trust_store.certificates:
            self.trusted_certs[hash_certificate_sha256(c).value] = c
            self.trusted_certs[hash_certificate_sha512(c).value] = c

    def verify_certificate(self, cert: Certificate, usage: CertificateUsage) -> None:
        """Verify a certificate against a trust store."""

        # Check the validity window and usage
        now = datetime.datetime.now().timestamp()
        if now < cert.valid_from or now >= cert.valid_from + cert.valid_length:
            raise Exception("current timestamp is outside certificate validity window")
        if usage not in cert.usages:
            raise Exception("not a server certificate")

        # Find the issuer cert
        if not cert.HasField("issuer"):
            raise Exception("no issuer")
        ca_cert = self.trusted_certs.get(cert.issuer.value)
        if ca_cert is None:
            raise Exception("unknown issuer")

        # Check the issuer's validity window and usage
        if now < ca_cert.valid_from or now >= ca_cert.valid_from + ca_cert.valid_length:
            raise Exception("current timestamp is outside CA certificate validity window")
        if CertificateUsage.CERTIFICATE_SIGNING not in ca_cert.usages:
            raise Exception("not a CA certificate")

        # Verify the issuer signature
        state = crypto_sign_ed25519ph_state()
        self._certificate_signature_state(state, cert, False)
        crypto_sign_ed25519ph_final_verify(state, cert.issuer_signature, ca_cert.signing_public_key)

    def verify_server_certificate(self, cert: Certificate, subject: str) -> None:
        """Verify a server certificate."""

        logging.debug("verifying server certificate")
        self.verify_certificate(cert, CertificateUsage.SERVER_AUTHENTICATION)
        if all([x != subject for x in cert.subjects]):
            raise Exception("subject mismatch")

    def verify_status_certificate(self, status_cert: Certificate, subject: str) -> None:
        """Verify a status certificate."""

        logging.debug("verifying status certificate")
        self.verify_certificate(status_cert, CertificateUsage.STATUS_SIGNING)
        if all([x != subject for x in status_cert.subjects]):
            raise Exception("subject mismatch")

    def verify_server_certificate_status(self,
                                         cert: Certificate,
                                         status: CertificateStatusResponse,
                                         status_subject: str) -> None:
        """Verify a server certificate status against a trust store."""

        logging.debug("verifying server certificate status")

        # Check that the status hash matches
        if status.certificate.algorithm == HashAlgorithm.SHA256:
            cert_hash = hash_certificate_sha256(cert)
        elif status.certificate.algorithm == HashAlgorithm.SHA512:
            cert_hash = hash_certificate_sha512(cert)
        else:
            raise Exception(f"unsupported hash algorithm {status.certificate.algorithm}")

        if cert_hash.value != status.certificate.value:
            raise Exception("certificate and status response mismatch")

        # Check the validity window
        now = datetime.datetime.now().timestamp()
        if now < status.valid_from or now >= status.valid_from + status.valid_length:
            raise Exception("current timestamp is outside status validity window")

        # Check the status certificate
        self.verify_status_certificate(status.status_certificate, status_subject)

        # Verify the status signature
        state = crypto_sign_ed25519ph_state()
        self._status_signature_state(state, status)
        crypto_sign_ed25519ph_final_verify(state, status.status_signature, status.status_certificate.signing_public_key)

        # Finally, check the actual status
        if status.status != CertificateStatus.VALID:
            raise Exception(f"certificate is not valid (status={status.status}")

    @staticmethod
    def _certificate_signature_state(state, cert: Certificate, include_signature: bool) -> None:
        """Collect signature state over a certificate."""

        for s in cert.subjects:
            crypto_sign_ed25519ph_update(state, s.encode("UTF-8"))
        crypto_sign_ed25519ph_update(state, struct.pack(">Q", cert.valid_from))
        crypto_sign_ed25519ph_update(state, struct.pack(">I", cert.valid_length))
        for u in cert.usages:
            if u == CertificateUsage.CERTIFICATE_SIGNING:
                crypto_sign_ed25519ph_update(state, bytes([0]))
            elif u == CertificateUsage.CLIENT_AUTHENTICATION:
                crypto_sign_ed25519ph_update(state, bytes([1]))
            elif u == CertificateUsage.SERVER_AUTHENTICATION:
                crypto_sign_ed25519ph_update(state, bytes([2]))
            elif u == CertificateUsage.STATUS_SIGNING:
                crypto_sign_ed25519ph_update(state, bytes([3]))
            else:
                raise Exception(f"invalid certificate usage {u}")
        crypto_sign_ed25519ph_update(state, cert.encryption_public_key)
        crypto_sign_ed25519ph_update(state, cert.signing_public_key)

        if cert.HasField("issuer"):
            crypto_sign_ed25519ph_update(state, cert.issuer.value)
            if cert.issuer.algorithm == HashAlgorithm.SHA256:
                crypto_sign_ed25519ph_update(state, bytes([1]))
            elif cert.issuer.algorithm == HashAlgorithm.SHA512:
                crypto_sign_ed25519ph_update(state, bytes([2]))
            else:
                raise Exception(f"unsupported hash algorithm {cert.issuer.algorithm}")

        if include_signature:
            crypto_sign_ed25519ph_update(state, cert.issuer_signature)

    @staticmethod
    def _status_signature_state(state, status: CertificateStatusResponse) -> None:
        """Collect signature state over a status."""

        CertificateVerifier._certificate_hash_signature_state(state, status.certificate)
        if status.status == CertificateStatus.UNKNOWN:
            crypto_sign_ed25519ph_update(state, bytes([0]))
        elif status.status == CertificateStatus.VALID:
            crypto_sign_ed25519ph_update(state, bytes([1]))
        elif status.status == CertificateStatus.INVALID:
            crypto_sign_ed25519ph_update(state, bytes([2]))
        else:
            raise Exception(f"invalid certificate status {status.status}")

        crypto_sign_ed25519ph_update(state, struct.pack(">Q", status.valid_from))
        crypto_sign_ed25519ph_update(state, struct.pack(">I", status.valid_length))

        CertificateVerifier._certificate_signature_state(state, status.status_certificate, True)

    @staticmethod
    def _certificate_hash_signature_state(state, cert: CertificateHash) -> None:
        """Collect signature state over a certificate hash."""

        crypto_sign_ed25519ph_update(state, cert.value)
        if cert.algorithm == HashAlgorithm.SHA256:
            crypto_sign_ed25519ph_update(state, bytes([1]))
        elif cert.algorithm == HashAlgorithm.SHA512:
            crypto_sign_ed25519ph_update(state, bytes([2]))
        else:
            raise Exception(f"unsupported hash algorithm {cert.algorithm}")


def hash_certificate(cert: Certificate, h, a: HashAlgorithm) -> CertificateHash:
    """Hash a certificate using SHA-256."""

    for s in cert.subjects:
        h.update(s.encode("UTF-8"))
    h.update(struct.pack(">Q", cert.valid_from))
    h.update(struct.pack(">I", cert.valid_length))
    for u in cert.usages:
        if u == CertificateUsage.CERTIFICATE_SIGNING:
            h.update(bytes([0]))
        elif u == CertificateUsage.CLIENT_AUTHENTICATION:
            h.update(bytes([1]))
        elif u == CertificateUsage.SERVER_AUTHENTICATION:
            h.update(bytes([2]))
        elif u == CertificateUsage.STATUS_SIGNING:
            h.update(bytes([3]))
        else:
            raise Exception(f"unknown certificate usage {u}")
    h.update(cert.encryption_public_key)
    h.update(cert.signing_public_key)

    if cert.HasField("issuer"):
        h.update(cert.issuer.value)
        if cert.issuer.algorithm == HashAlgorithm.SHA256:
            h.update(bytes([1]))
        elif cert.issuer.algorithm == HashAlgorithm.SHA512:
            h.update(bytes([2]))
        else:
            raise Exception(f"unsupported hash algorithm {cert.issuer.algorithm}")

    h.update(cert.issuer_signature)

    x = CertificateHash()
    x.value = h.digest()
    x.algorithm = a
    return x
