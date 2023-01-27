from __future__ import annotations  # 3.10 style

import bson
from dataclasses import dataclass
from typing import Any
import sys

from Cryptodome.Cipher import AES


# Abstract
class Message:
    def serialize(self) -> bytes:
        # ToDo: convert types to ints, lower overhead
        self._type = self.__class__.__name__
        # ToDo: recurse
        return bson.encode(self.__dict__)

    def deserialize(self) -> Any:
        try:
            decoded = bson.decode(self.msg)
        except bson.errors.InvalidBSON:
            # print(self.msg)
            raise
        klass = getattr(sys.modules[__name__], decoded["_type"])
        del decoded["_type"]
        return klass(**decoded)

    def encrypt(self, key) -> Any:
        """Take a bytes stream and AES key and encrypt it"""
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(self.serialize())
        return EncryptedMessage(cipher.nonce.hex(), tag.hex(), ciphertext.hex())

    def as_dict(self):
        return self.__dict__


@dataclass
class ChallengeReplyMessage(Message):
    id: str = ""
    signature: str = ""
    close_connection: bool = False


@dataclass
class ChallengeMessage(Message):
    id: str = ""
    to_sign: str = ""
    address: str = ""
    auth_required: bool = True
    source: tuple = ()


@dataclass
class AuthReplyMessage(Message):
    authenticated: bool = False
    source: tuple = ()


@dataclass
class ErrorMessage(Message):
    error: str


@dataclass
class SerializedMessage(Message):
    msg: bytes


@dataclass
class RpcReplyMessage(Message):
    payload: bytes


@dataclass
class RpcRequestMessage(Message):
    payload: bytes


@dataclass
class PtyMessage(Message):
    data: bytes


@dataclass
class PtyResizeMessage(Message):
    rows: int = 0
    cols: int = 0


@dataclass
class PtyClosedMessage(Message):
    reason: str


@dataclass
class SessionKeyMessage(Message):
    aes_key_message: bytes
    rsa_encrypted_session_key: str


@dataclass
class AesKeyMessage(Message):
    aes_key: str


@dataclass
class RsaPublicKeyMessage(Message):
    key: str


@dataclass
class EncryptedMessage(Message):
    nonce: str
    tag: str
    ciphertext: str

    def decrypt(self, key):
        nonce = bytes.fromhex(self.nonce)
        tag = bytes.fromhex(self.tag)
        ciphertext = bytes.fromhex(self.ciphertext)
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        self.msg = cipher.decrypt_and_verify(ciphertext, tag)
        return self.deserialize()


@dataclass
class TestMessage(Message):
    fill: bytes
    text: str = "TestEncryptionMessage"


@dataclass
class ProxyMessage(Message):
    proxy_required: bool = False
    proxy_target: str = ""
    proxy_port: int | None = None
    proxy_ssl_required: bool = False


@dataclass
class ProxyResponseMessage(Message):
    success: bool
    socket_details: tuple = ()


@dataclass
class FingerprintMessage(Message):
    ...


@dataclass
class FingerprintResponseMessage(Message):
    verify_source_address: bool
    whitelisted_addresses: list
    authentication_required: bool
    authentication_address: str
    ssl: bool
