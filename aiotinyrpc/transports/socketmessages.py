from __future__ import annotations  # 3.10 style

import bson
from dataclasses import dataclass
from typing import Any
import sys

import bson
from Cryptodome.Cipher import AES

# Abstract
class Message:
    def serialize(self) -> bytes:
        self._type = self.__class__.__name__
        # ToDo: recurse
        return bson.encode(self.__dict__)

    def deserialize(self) -> Any:
        decoded = bson.decode(self.msg)
        klass = getattr(sys.modules[__name__], decoded["_type"])
        del decoded["_type"]
        return klass(**decoded)

    def encrypt(self, key) -> Any:
        """Take a bytes stream and AES key and encrypt it"""
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(self.serialize())
        return EncryptedMessage(cipher.nonce.hex(), tag.hex(), ciphertext.hex())

    # def as_dict(self):
    #     return self.__dict__


# ToDO: change this module name to messages and remove message from every class
# cleaner


# these 3 shouldn't be here. They are specific to signature auth but I was getting
# grief with circular imports


@dataclass
class ChallengeReplyMessage(Message):
    signature: str


@dataclass
class ChallengeMessage(Message):
    to_sign: str
    address: str


@dataclass
class AuthReplyMessage(Message):
    authenticated: bool


###


@dataclass
class ErrorMessage(Message):
    error: str


@dataclass
class SerializedMessage(Message):
    msg: bytes


@dataclass
class RpcReplyMessage(Message):
    msg: bytes


@dataclass
class RpcRequestMessage(Message):
    msg: bytes


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
    response: bool
