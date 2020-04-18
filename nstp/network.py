"""Protocol implementation."""

import asyncio
import hashlib
import logging
import os
import struct

from nacl.bindings import \
    crypto_kx_client_session_keys, \
    crypto_secretbox, \
    crypto_secretbox_open, \
    crypto_secretbox_NONCEBYTES, \
    sodium_increment

from nstp_v4_pb2 import *
from pki import CertificateVerifier, hash_certificate_sha256


class StatusClientProtocol(asyncio.DatagramProtocol):
    """NSTP status client protocol."""

    def __init__(self, cert: Certificate, on_result: asyncio.Future) -> None:
        """Initialize the protocol."""

        self.certificate = cert
        self.on_result = on_result
        self.transport = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        message = CertificateStatusRequest()
        message.certificate.CopyFrom(hash_certificate_sha256(self.certificate))
        data = message.SerializeToString()
        self.transport.sendto(data)

    def datagram_received(self, data: bytes, _) -> None:
        message = CertificateStatusResponse()
        message.ParseFromString(data)
        self.on_result.set_result(message)

    def error_received(self, exception: Exception) -> None:
        logging.error("error while querying status server", exc_info=exception)
        self.on_result.set_result(None)

    def connection_lost(self, exception: Exception) -> None:
        pass


class Session(object):
    """NSTP session."""

    def __init__(self,
                 trust_store: CertificateStore,
                 client_cert: Certificate,
                 client_key: PrivateKey,
                 status_server_address: str,
                 status_server_port: int) -> None:
        """Create a session."""

        self.trust_store = trust_store
        self.verifier = CertificateVerifier(self.trust_store)
        self.client_cert = client_cert
        self.client_key = client_key
        self.status_server_address = status_server_address
        self.status_server_port = status_server_port
        self.reader = None
        self.writer = None
        self.reader_key = None
        self.writer_key = None
        self.writer_nonce = os.urandom(crypto_secretbox_NONCEBYTES)

    async def initialize(self, server_address: str, server_port: int) -> None:
        """Initialize an NSTP connection."""

        if self.reader is not None:
            raise Exception("session has already been initialized")

        self.reader, self.writer = await asyncio.open_connection(server_address, server_port)

        # Send a hello
        m = NSTPMessage()
        m.client_hello.major_version = 4
        m.client_hello.minor_version = 0
        m.client_hello.user_agent = "nstpc"
        m.client_hello.certificate.CopyFrom(self.client_cert)
        logging.debug(f"SEND {m}")
        m_data = m.SerializeToString()
        self.writer.write(struct.pack(">H", len(m_data)))
        self.writer.write(m_data)
        await self.writer.drain()

        # Receive a hello
        m = NSTPMessage()
        m_length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        m.ParseFromString(await self.reader.readexactly(m_length))
        logging.debug(f"RECV {m}")
        m_type = m.WhichOneof("message_")
        if m_type != "server_hello":
            raise Exception(f"expected server hello, received {m_type}")
        if m.server_hello.major_version != 4:
            raise Exception(f"invalid server major version {m.server_hello.major_version}")

        self.verifier.verify_server_certificate(m.server_hello.certificate, server_address)
        if m.server_hello.HasField("certificate_status"):
            status = m.server_hello.certificate_status
        else:
            status = await self.fetch_certificate_status(m.server_hello.certificate)

        self.verifier.verify_server_certificate_status(m.server_hello.certificate, status, self.status_server_address)

        # Establish session keys
        self.reader_key, self.writer_key = \
            crypto_kx_client_session_keys(self.client_cert.encryption_public_key,
                                          self.client_key.encryption_private_key,
                                          m.server_hello.certificate.encryption_public_key)
        
        logging.info("session initialized")

    async def ping(self) -> None:
        """Ping the server."""

        if not self.reader_key:
            raise Exception("session has not been initialized")

        m = DecryptedMessage()
        m.ping_request.data = os.urandom(16)
        data_hash = hashlib.sha512(m.ping_request.data).digest()
        m.ping_request.hash_algorithm = HashAlgorithm.SHA512
        await self._send_encrypted(m)

        m = await self._receive_encrypted()
        m_type = m.WhichOneof("message_")
        if m_type != "ping_response":
            raise Exception(f"expected ping response, received {m_type}")
        if m.ping_response.hash != data_hash:
            raise Exception("invalid ping response")

    async def load_data(self, key: str, public: bool) -> bytes:
        """Load data from the server."""

        if not self.reader_key:
            raise Exception("session has not been initialized")
        
        m = DecryptedMessage()
        m.load_request.key = key
        m.load_request.public = public
        await self._send_encrypted(m)
        
        m = await self._receive_encrypted()
        m_type = m.WhichOneof("message_")
        if m_type != "load_response":
            raise Exception(f"expected load response, received {m_type}")
        
        return m.load_response.value

    async def store_data(self, key: str, value: bytes, public: bool) -> None:
        """Store data at the server."""

        if not self.reader_key:
            raise Exception("session has not been initialized")
        
        m = DecryptedMessage()
        m.store_request.key = key
        m.store_request.value = value
        m.store_request.public = public
        await self._send_encrypted(m)
        
        m = await self._receive_encrypted()
        m_type = m.WhichOneof("message_")
        if m_type != "store_response":
            raise Exception(f"expected store response, received {m_type}")
        
        if m.store_response.hash_algorithm == HashAlgorithm.IDENTITY:
            value_hash = value
        elif m.store_response.hash_algorithm == HashAlgorithm.SHA256:
            value_hash = hashlib.sha256(value).digest()
        elif m.store_response.hash_algorithm == HashAlgorithm.SHA512:
            value_hash = hashlib.sha512(value).digest()
        else:
            raise Exception(f"unsupported hash algorithm {m.store_response.hash_algorithm}")
        if value_hash != m.store_response.hash:
            raise Exception("store response hash mismatch")

    async def fetch_certificate_status(self, cert: Certificate) -> CertificateStatusResponse:
        """Fetch a certificate status for a certificate."""

        loop = asyncio.get_running_loop()
        on_result = loop.create_future()
        remote = (self.status_server_address, self.status_server_port)
        transport, protocol = await loop.create_datagram_endpoint(lambda: StatusClientProtocol(cert, on_result),
                                                                  remote_addr=remote)

        try:
            await on_result
            result = on_result.result()
            if result is None:
                raise Exception("unable to fetch server certificate status")
            return result
        finally:
            transport.close()

    async def _send_encrypted(self, m: DecryptedMessage):
        """Send an encrypted message."""

        e = NSTPMessage()
        e.encrypted_message.ciphertext = crypto_secretbox(m.SerializeToString(), self.writer_nonce, self.writer_key)
        e.encrypted_message.nonce = self.writer_nonce
        sodium_increment(self.writer_nonce)
        message_data = e.SerializeToString()
        self.writer.write(message_data)
        await self.writer.drain()

    async def _receive_encrypted(self) -> DecryptedMessage:
        """Receive an encrypted message."""

        e = NSTPMessage()
        e_length = struct.unpack(">H", await self.reader.readexactly(2))[0]
        e.ParseFromString(await self.reader.readexactly(e_length))
        e_type = e.WhichOneof("message_")
        if e_type != "encrypted_message":
            raise Exception(f"expected encrypted message, received {e_type}")

        m = DecryptedMessage()
        m.ParseFromString(crypto_secretbox_open(e.encrypted_message.ciphertext,
                                                e.encrypted_message.nonce,
                                                self.reader_key))
        return m
