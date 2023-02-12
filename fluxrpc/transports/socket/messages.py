from __future__ import annotations  # 3.10 style

import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any

import bson


class MessageTypes(Enum):
    ChallengeMessage = 1
    ChallengeReplyMessage = 2
    AuthReplyMessage = 3
    ErrorMessage = 4
    SerializedMessage = 5
    RpcRequestMessage = 6
    RpcReplyMessage = 7
    PtyMessage = 8
    PtyResizeMessage = 9
    PtyClosedMessage = 10
    SessionKeyMessage = 11
    AesKeyMessage = 12
    RsaPublicKeyMessage = 13
    EncryptedMessage = 14
    TestMessage = 15
    ProxyMessage = 16
    ProxyResponseMessage = 17
    FileEntryStreamMessage = 18

from Cryptodome.Cipher import AES


# Abstract
class Message:
    def serialize(self) -> bytes:
        # ToDo: convert types to ints, lower overhead
        try:
            # figure it's cheaper to transmit ints that strings. Probably
            # should use structs
            self._type = MessageTypes[self.__class__.__name__].value
        except Exception as e:
            print('trying to serialize')
            print(repr(e))

        # ToDo: recurse
        return bson.encode(self.__dict__)

    def deserialize(self) -> Any:
        try:
            decoded = bson.decode(self.msg)
        except bson.errors.InvalidBSON:
            # print(self.msg)
            raise

        klass = getattr(sys.modules[__name__], MessageTypes(decoded["_type"]).name)
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
class FileEntryStreamMessage(Message):
    data: bytes
    path: str = ""
    eof: bool = False