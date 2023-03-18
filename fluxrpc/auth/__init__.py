from __future__ import annotations

from bitcoin.base58 import Base58Error
from bitcoin.signmessage import BitcoinMessage, SignMessage, VerifyMessage
from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from Cryptodome.Random import get_random_bytes

from fluxrpc.transports.socket.messages import (
    AuthReplyMessage,
    ChallengeMessage,
    ChallengeReplyMessage,
)


class AuthProvider:
    """All auth providers inherit from this"""

    def auth_message(self):
        raise NotImplementedError

    def verify_auth_message(self):
        raise NotImplementedError


class SignatureAuthProvider(AuthProvider):
    def __init__(self, key: str | None = None, address: str | None = None):
        self.key = key
        self.address = address
        self.challenges = {}

        self.to_sign = None

    def sign_message(self, to_sign):
        try:
            secret = CBitcoinSecret(self.key)
        except Base58Error:
            raise ValueError

        message = BitcoinMessage(to_sign)
        return SignMessage(secret, message)

    def verify_message(self, address: str, msg: str, sig: str):
        msg = BitcoinMessage(msg)
        return VerifyMessage(address, msg, sig)

    def auth_message(self, id, to_sign):
        """Creates a message (non serialized) to be sent to the authenticator.
        In this case the message is a Bitcoin signed message"""
        # this happens if someone passes in bad key data. Upper layer can
        # catch ValueError
        try:
            secret = CBitcoinSecret(self.key)
        except Base58Error:
            raise ValueError

        message = BitcoinMessage(to_sign)
        return ChallengeReplyMessage(id, SignMessage(secret, message))

    def verify_auth(self, auth_msg: ChallengeReplyMessage):
        sig = auth_msg.signature
        to_sign = self.challenges.pop(auth_msg.id, None)
        if not to_sign:
            auth_state = False
        else:
            msg = BitcoinMessage(to_sign)
            auth_state = VerifyMessage(self.address, msg, sig)
        return auth_state

    def generate_challenge(self, msg: ChallengeMessage):
        if not self.address:
            raise ValueError("Address must be provided")

        id = get_random_bytes(16).hex()
        to_sign = get_random_bytes(16).hex()
        self.challenges.update({id: to_sign})

        msg.id = id
        msg.to_sign = to_sign
        msg.address = self.address

        return msg
