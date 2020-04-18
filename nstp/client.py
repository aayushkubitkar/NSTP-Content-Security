"""NSTP client."""

import asyncio
import logging
from pathlib import Path
from typing import Any
import struct

import click
# from nacl.bindings import sodium_init

from network import Session
from pki import load_certificate, load_private_key, load_trust_store
from interpreter import Interpreter
from nstp_v4_pb2 import *

async def execute_client(session: Session,
                         server_address: str, 
                         server_port: int, 
                         key: str,
                         trust_store: CertificateStore,
                         client_cert: Certificate,
                         client_key: PrivateKey,
                         status_server_address: str,
                         status_server_port: int) -> Any:
    """Execute a client."""

    # Initialize the session
    await session.initialize(server_address, int(server_port))
    logging.info(f"session initialized with {server_address}:{server_port}")
    origin = (server_address, int (server_port))
    await session.ping()
    # await session.store_data("initial.js", bytes("document.log('success')", "utf-8"), True)

    # Fetch the key
    value = await session.load_data(key, True)
    suffix='.js'
    try:
        val = value.decode("utf-8")
        if val.endswith(suffix):
            logging.info("key is JS")
            # TODO: Evaluate the associated content?
            js_obj = Interpreter(trust_store, client_cert, client_key, status_server_address, status_server_port)
            js_obj.evaluate(val)
        else:
            logging.info(f"key is not a JS but {val}")
    except UnicodeDecodeError:
        logging.info(f"key is not a string but {value}")
    logging.info("Exiting client")

@click.command()
@click.option("-c", "--client-certificate", required=True)
@click.option("-d", "--debug", default=False, is_flag=True)
@click.option("-k", "--key", required=True)
@click.option("-p", "--client-private-key", required=True)
@click.option("-s", "--server-address", required=True)
@click.option("-t", "--trust-store", required=True)
@click.option("-v", "--status-server-address", required=True)
def main(client_certificate: str,
         debug: bool,
         key: str,
         client_private_key: str,
         server_address: str,
         trust_store: str,
         status_server_address: str) -> None:
    # sodium_init()
    level = logging.INFO
    if debug:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)-5s %(asctime)-15s > %(message)s")

    logging.debug("loading PKI data")
    trust_store = load_trust_store(Path(trust_store))
    client_cert = load_certificate(Path(client_certificate))
    client_key = load_private_key(Path(client_private_key))

    # Establish a session
    logging.info(f"establishing a session with {server_address}")
    status_server_address, status_server_port = status_server_address.split(":")
    session = Session(trust_store, client_cert, client_key, status_server_address, int(status_server_port))
    server_address, server_port = server_address.split(":")
    asyncio.run(execute_client(session, server_address, server_port, key, trust_store, client_cert, client_key, status_server_address, int(status_server_port)))


if __name__ == "__main__":
    main()
