"""
Module for working with PIV based on UserKey class
"""
from hashlib import sha256


import cryptnoxpy
from cryptography import x509
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_pem_public_key, load_pem_private_key
from stdiomask import getpass
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from pathlib import Path

from .. import user_key_base


class Pem(user_key_base.UserKey):
    """
    Class for handling loading user key from PEM file.
    """
    name = "pem"
    description = "PEM applet"
    slot_index = cryptnoxpy.SlotIndex.EC256R1

    def delete(self):
        pass

    @property
    def public_key(self) -> bytes:

        with open(f"{Path.home()}/.cryptnoxkeys/uk/public_key.pem","rb") as pem_file:
            public_key = load_pem_public_key(pem_file.read())

        return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)

    def sign(self, message: bytes) -> bytes:

        with open(f"{Path.home()}/.cryptnoxkeys/uk/private_key.pem","rb") as pem_file:
            private_key = load_pem_private_key(pem_file.read(),password=None)

        signature = private_key.sign(message,ec.ECDSA(hashes.SHA256()))
        
        return signature

