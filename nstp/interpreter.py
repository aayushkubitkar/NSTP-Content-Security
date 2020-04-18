"""Interpreter implementation."""

from typing import Any
import logging
import pyduktape

from pki import *
from network import Session
from pki import load_certificate, load_private_key, load_trust_store
from nstp_v4_pb2 import *

class Document(object):
    """NSTP document."""

    def __init__(self) -> None:
        """Initializer."""
        self.client = {userAgent:"nstpc", majorVersion:4, minorVersion:0}
        self.localStorage = {}
    @staticmethod
    def log(message: str) -> None:
        """Log a message to the console."""
        logging.info(f"[JS] {message}")
    
    async def remoteLoad(self, nstpUrl: str) -> bytes:
        logging.info("inside remote Load")
        tmp = nstpUrl.split(":")
        server_address = tmp[0][7:]
        server_port = tmp[1].split("/")[0]
        key = tmp[1].split("/")[1]
        #Establish a new session for the origin
        session = Session(self.trust_store, self.client_cert, self.client_key, self.status_server_address, self.status_server_port)
        await session.initialize(server_address,int(server_port))
        value = await session.load_data(key, True)
        suffix='.js'
        try:
            val = value.decode("utf-8")
            if val.endswith(suffix):
                logging.info("key is JS")
                # TODO: Evaluate the associated content?
                return self.evaluate(val)
            else:
                logging.info(f"key is not a JS but {val}")
        except UnicodeDecodeError:
            logging.info(f"key is not a string but {value}")
        return value

    async def remoteStore(nstpUrl: str, value: bytes) -> None:
        logging.info("inside remote Load")
        tmp = nstpUrl.split(":")
        server_address = tmp[0][7:]
        server_port = tmp[1].split("/")[0]
        key = tmp[1].split("/")[1]
        #Establish a new session for the origin
        session = Session(self.trust_store, self.client_cert, self.client_key, self.status_server_address, self.status_server_port)
        await session.initialize(server_address,int(server_port))
        await session.store_data(key, value, True)
        
class Interpreter(object):
    """NSTP JavaScript interpreter."""

    def __init__(self,
                 trust_store: CertificateStore,
                 client_cert: Certificate,
                 client_key: PrivateKey,
                 status_server_address: str,
                 status_server_port: int) -> None:

        """Initializer."""
        self.trust_store = trust_store
        self.client_cert = client_cert
        self.client_key = client_key
        self.status_server_address = status_server_address
        self.status_server_port = status_server_port
        self.context = pyduktape.DuktapeContext()
        self.context.set_globals(document=Document(self))

    def evaluate(self, value: str) -> Any:
        """Evaluate a program."""
        logging.info("in the JS evaluate method")
        res = self.context.eval_js("value")
        logging.info(res)
        return res
        
