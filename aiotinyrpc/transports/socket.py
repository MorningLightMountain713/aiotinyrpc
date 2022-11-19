from __future__ import annotations  # 3.10 style

import asyncio
from typing import Any, Callable

import bson
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from aiotinyrpc.log import log
from aiotinyrpc.transports import ClientTransport, ServerTransport
from aiotinyrpc.auth import AuthProvider


def encrypt_aes_data(key, message: bytes) -> str:
    """Take a bytes stream and AES key and encrypt it"""
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    jdata = {
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
    }
    return bson.encode(jdata)


# ToDo: these aes encrypt / decrypt functions double encrypt
def decrypt_aes_data(key, data: bytes) -> dict:
    """Take a bytes stream and AES key and decrypt it"""
    # ToDo: Error checking
    try:
        jdata = bson.decode(data)
        nonce = bytes.fromhex(jdata["nonce"])
        tag = bytes.fromhex(jdata["tag"])
        ciphertext = bytes.fromhex(jdata["ciphertext"])
        # let's assume that the key is somehow available again
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        msg = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise
    return bson.decode(msg)


class EncryptedSocketClientTransport(ClientTransport):
    """ToDo: this docstring"""

    def __init__(
        self,
        address: str,
        port: int,
        debug: bool = False,
        auth_provider: AuthProvider | None = None,
    ):
        self._address = address
        self._port = port
        self._connected = False
        self.debug = debug
        self.is_async = True
        self.encrypted = False
        self.seperator = b"<?!!?>"
        self.loop = asyncio.get_event_loop()
        self.reader, self.writer = None, None
        self.auth_provider = auth_provider

        # Removed this... up to the client how they want to proceed
        # self.connect()

    def serialize(self, msg: Any) -> bytes:
        """Converts any object to json and encodes in as bytes, reading for sending"""
        return bson.encode(msg)

    def deserialize(self, msg: bytes) -> Any:
        return bson.decode(msg)

    def encrypt_aes_key(self, keypem: str, data: str) -> dict:
        """Generate and encrypt AES session key with RSA public key"""
        key = RSA.import_key(keypem)
        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        msg = {
            "enc_session_key": enc_session_key.hex(),
            "nonce": cipher_aes.nonce.hex(),
            "tag": tag.hex(),
            "cipher": ciphertext.hex(),
        }
        return msg

    async def setup_encryption(self):
        """Once the socket is connected, the encryption process begins.
        1/ Server sends RSA public key
        2/ Client creates an AES session key and encrypts it with public RSA key
        3/ Server decrypts AES session key and uses it to generate an encrypted test message
        4/ Client decrypts AES message, reverses the random data and sends it back
        5/ Link is now confirmed by both ends to be encrypted
        6/ Encrypted flag is set - any further messages will be AES protected"""

        # ToDo: maybe get the other end to return a useful message here if authentication failed
        rsa_public_key = await self.wait_for_message()
        rsa_public_key = rsa_public_key.decode("utf-8")
        self.aeskey = get_random_bytes(16).hex().encode("utf-8")
        try:
            encrypted_aes_key = self.encrypt_aes_key(rsa_public_key, self.aeskey)
        except ValueError:
            log.error("Malformed (or no) RSA key received... skipping")
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False
            return

        test_message = await self.send_message(self.serialize(encrypted_aes_key))
        decrypted_test_message = decrypt_aes_data(self.aeskey, test_message)

        if not decrypted_test_message.get("text") == "TestEncryptionMessage":
            log.error("Malformed test aes message received... skipping")
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False
            return

        self.encrypted = True

        reversed_fill = decrypted_test_message.get("fill")[::-1]
        msg = {"text": "TestEncryptionMessageResponse", "fill": reversed_fill}
        await self.send_message(self.serialize(msg), expect_reply=False)

    async def authenticate(self):
        challenge = await self.wait_for_message()
        try:
            challenge = self.deserialize(challenge)
        except bson.errors.InvalidBSON:
            log.error("Invalid authenticate message received")
            return False

        msg = challenge.get("to_sign")
        try:
            auth_message = self.auth_provider.auth_message(msg)
        except ValueError:
            log.error("Malformed private key... you need to reset key")
            return False

        res = await self.send_message(self.serialize(auth_message))
        res = self.deserialize(res)
        return res.get("authenticated", False)

    def connect(self):
        self.loop.run_until_complete(self._connect())

        if not self.reader and not self.writer:
            return

        if self.auth_provider:
            authenticated = self.loop.run_until_complete(self.authenticate())
            if not authenticated:
                return
            log.info("Connection authenticated!")

        self._connected = True

        self.loop.run_until_complete(self.setup_encryption())

    async def _connect(self):
        """Connects to socket server. Tries a max of 3 times"""
        log.info(f"Opening connection to {self._address} on port {self._port}")
        retries = 3

        for n in range(retries):
            con = asyncio.open_connection(self._address, self._port)
            try:
                self.reader, self.writer = await asyncio.wait_for(con, timeout=3)

                break

            except asyncio.TimeoutError:
                log.warn(f"Timeout error connecting to {self._address}")
            except ConnectionError:
                log.warn(f"Connection error connecting to {self._address}")
            await asyncio.sleep(n)

    @property
    def connected(self) -> bool:
        """If the socket is connected or not"""
        return self._connected

    async def wait_for_message(self) -> bytes:
        # ToDo: bit naff serialing again after decrypting. Fix that up
        """Blocks waiting for a message on the socket until seperator is received"""
        # ToDo: make this error handling a bit better. E.g. if authentication fails,
        # this error will get raised instead of letting the client know
        try:
            data = await self.reader.readuntil(separator=self.seperator)
        except asyncio.IncompleteReadError as e:
            log.error("EOF reached, socket closed")
            self._connected = False
            self.encrypted = False
            return ""

        message = data.rstrip(self.seperator)
        if self.encrypted:
            message = decrypt_aes_data(self.aeskey, message)
            message = self.serialize(message)

        return message

    async def send_message(self, message: bytes, expect_reply: bool = True):
        """Writes data on the socket"""
        if self.encrypted:
            log.debug(f"Sending encrypted message (decoded): {bson.decode(message)}")
            message = encrypt_aes_data(self.aeskey, message)
        else:
            log.debug(f"Sending message in the clear (decoded): {bson.decode(message)}")

        self.writer.write(message + self.seperator)
        await self.writer.drain()
        log.debug("Message sent!")

        if expect_reply:
            return await self.wait_for_message()

    def disconnect(self):
        self._connected = False
        self.encrypted = False
        self.loop.run_until_complete(self._close_socket())

    async def _close_socket(self):
        """Lets other end know we're closed, then closes socket"""
        if self.writer and not self.writer.is_closing():
            self.writer.write_eof()
            self.writer.close()
            await self.writer.wait_closed()
        self.reader = None
        self.writer = None

    def __del__(self):
        self.disconnect()


class EncryptedSocketServerTransport(ServerTransport):
    def __init__(
        self,
        address: str,
        port: int,
        whitelisted_addresses: list = [],
        verify_source_address: bool = True,
        auth_provider: AuthProvider | None = None,
        debug: bool = False,
    ):
        self._address = address
        self._port = port
        self.is_async = True
        self.debug = debug
        self.sockets = {}
        self.messages = []
        self.seperator = b"<?!!?>"
        # ToDo: validate addresses
        self.whitelisted_addresses = whitelisted_addresses
        self.verify_source_address = verify_source_address
        self.auth_provider = auth_provider

    def serialize(self, msg: Any) -> bytes:
        """Converts any object to json and encodes in as bytes, reading for sending"""
        return bson.encode(msg)

    def deserialize(self, msg: bytes) -> Any:
        return bson.decode(msg)

    def decrypt_aes_key(self, keypem: str, cipher: dict) -> str:
        """Used by Node to decrypt and return the AES Session key using the RSA Key"""
        private_key = RSA.import_key(keypem)
        enc_session_key = bytes.fromhex(cipher["enc_session_key"])
        nonce = bytes.fromhex(cipher["nonce"])
        tag = bytes.fromhex(cipher["tag"])
        ciphertext = bytes.fromhex(cipher["cipher"])

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data

    async def encrypt_socket(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.generate_key_data(peer)

        # ToDo: does receive_on_socket need to return peer?
        await self.send(writer, self.sockets[peer]["key_data"]["Public"])

        try:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            _, encrypted_aes_key = await asyncio.wait_for(task, timeout=10)

        except (TypeError, asyncio.TimeoutError):
            log.error("Incorrect (or no) encryption message received... dropping")
            writer.close()
            await writer.wait_closed()
            return

        # ToDo: try / except
        aeskey = self.decrypt_aes_key(
            self.sockets[peer]["key_data"]["Private"], bson.decode(encrypted_aes_key)
        )
        self.sockets[peer]["key_data"]["AESKEY"] = aeskey

        # Send a test encryption request, always include random data
        random = get_random_bytes(16).hex()
        test_msg = {"text": "TestEncryptionMessage", "fill": random}
        # enc_msg = json.dumps(test_msg).encode()
        enc_msg = bson.encode(test_msg)
        # ToDo: this function should take dict, str or bytes
        encrypted_test_msg = encrypt_aes_data(aeskey, enc_msg)
        await self.send(writer, encrypted_test_msg)
        _, res = await self.receive_on_socket(peer, reader)
        response = decrypt_aes_data(aeskey, res)

        if (
            response.get("text") == "TestEncryptionMessageResponse"
            and response.get("fill") == random[::-1]
        ):
            self.sockets[peer]["encrypted"] = True
        log.info(f"Socket is encrypted: {self.sockets[peer]['encrypted']}")

    def generate_key_data(self, peer):
        rsa = RSA.generate(2048)
        rsa_private = rsa.export_key()
        rsa_public = rsa.publickey().export_key()
        self.sockets[peer]["key_data"] = {
            "RSAkey": rsa,
            "Private": rsa_private,
            "Public": rsa_public,
        }

    async def valid_source_ip(self, peer_ip) -> bool:
        """Called when connection is established to verify correct source IP"""
        if peer_ip not in self.whitelisted_addresses:
            # Delaying here doesn't really stop against a DoS attack so have lowered
            # this to 3 seconds. In fact, it makes it even easier to DoS as you have an
            # open socket consuming resources / port
            await asyncio.sleep(3)
            log.warn(
                f"Reject Connection, wrong IP: {peer_ip} Expected {self.whitelisted_addresses}"
            )
            return False
        return True

    async def authenticate(self, peer, reader, writer) -> bool:
        # all received messages need error handling
        challenge = self.auth_provider.challenge_message()
        await self.send(writer, self.serialize(challenge))

        try:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            _, challenge_reply = await asyncio.wait_for(task, timeout=10)

        except (TypeError, asyncio.TimeoutError):
            log.warn("Malformed (or no) challenge reply... dropping")
            writer.close()
            await writer.wait_closed()
            return False

        challenge_reply = self.deserialize(challenge_reply)
        authenticated = self.auth_provider.verify_auth(challenge_reply)
        await self.send(writer, self.serialize(self.auth_provider.auth_reply_message()))
        log.info(f"Auth provider authenticated: {authenticated}")
        if not authenticated:
            # ToDo: check this actually closes socket
            writer.close()
            await writer.wait_closed()
            return False
        return True

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        log.info(f"Peer connected: {peer}")

        self.sockets[peer] = {
            "encrypted": False,
            "reader": reader,
            "writer": writer,
            "key_data": {},
        }

        authenticated = True
        if self.auth_provider:
            authenticated = await self.authenticate(peer, reader, writer)

        if not authenticated:
            return

        if self.verify_source_address and not await self.valid_source_ip(peer[0]):
            log.warn("Source IP address not verified... dropping")
            writer.close()
            await writer.wait_closed()
            return

        await self.encrypt_socket(reader, writer)

        running = True

        while running:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            message = await asyncio.wait_for(task, None)

            if message:
                log.debug(
                    f"Message received (decrypted and decoded): {bson.decode(message[1])})"
                )
                self.messages.append(message)
            else:  # Socket closed
                running = False

    async def start_server(self):
        # ToDo: pass in variables
        self.server = await asyncio.start_server(
            self.handle_client, self._address, self._port, start_serving=True
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        log.info(f"Serving on {addrs}")

    async def receive_on_socket(self, peer, reader) -> tuple | None:
        if reader.at_eof():
            log.info(f"Remote peer {peer} sent EOF, closing socket")
            self.sockets[peer]["writer"].close()
            del self.sockets[peer]
            return None
        try:
            data = await reader.readuntil(separator=self.seperator)
        except asyncio.exceptions.IncompleteReadError:
            return None
        except asyncio.LimitOverrunError as e:
            data = []
            while True:
                current = await reader.read(64000)
                if current.endswith(self.seperator):
                    data.append(current)
                    break
                data.append(current)
            data = b"".join(data)

        message = data.rstrip(self.seperator)

        if self.sockets[peer]["encrypted"]:
            message = decrypt_aes_data(
                self.sockets[peer]["key_data"]["AESKEY"], message
            )
            message = bson.encode(message)

        return (peer, message)

    async def receive_message(self) -> tuple:
        while not self.messages:
            # ToDo: Set this via param, debug 0.5, prod 0.05
            await asyncio.sleep(0.05)

        addr, message = self.messages.pop(0)
        return addr, message

    async def send(self, writer, reply):
        writer.write(reply + self.seperator)
        await writer.drain()

    async def send_reply(self, context: tuple, reply: bytes):
        if self.sockets[context]["encrypted"]:
            reply = encrypt_aes_data(self.sockets[context]["key_data"]["AESKEY"], reply)

        writer = self.sockets[context]["writer"]
        await self.send(writer, reply)
