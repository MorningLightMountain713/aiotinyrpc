from __future__ import annotations  # 3.10 style
from typing import Any

import json
import bson

import asyncio

from aiotinyrpc.transports import ClientTransport, ServerTransport

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


def encrypt_aes_data(key, message: bytes) -> str:
    """Take a bytes stream and AES key and encrypt it"""
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    jdata = {
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "ciphertext": ciphertext.hex(),
    }
    # return json.dumps(jdata).encode("utf-8")
    return bson.encode(jdata)


def decrypt_aes_data(key, data: bytes) -> dict:
    """Take a bytes stream and AES key and decrypt it"""
    # ToDo: Error checking
    try:
        # jdata = json.loads(data.decode("utf-8"))
        jdata = bson.decode(data)
        nonce = bytes.fromhex(jdata["nonce"])
        tag = bytes.fromhex(jdata["tag"])
        ciphertext = bytes.fromhex(jdata["ciphertext"])
        # let's assume that the key is somehow available again
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        msg = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise
    # return json.loads(msg)
    return bson.decode(msg)


class EncryptedSocketClientTransport(ClientTransport):
    """ToDo"""

    def __init__(self, address: str, port: int):
        self._address = address
        self._port = port
        self._connected = False
        self.is_async = True
        self.encrypted = False
        self.seperator = b"<?!!?>"
        self.loop = asyncio.get_event_loop()
        self.reader, self.writer = None, None

        self.loop.run_until_complete(self.get_connection())

        if not self.reader and not self.writer:
            return

        self._connected = True

        self.loop.run_until_complete(self.setup_encryption())

    def serialize(self, msg: Any) -> bytes:
        """Converts any object to json and encodes in as bytes, reading for sending"""
        # return json.dumps(msg).encode()
        return bson.encode(msg)

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
        encrypted_aes_key = self.encrypt_aes_key(rsa_public_key, self.aeskey)

        test_message = await self.send_message(self.serialize(encrypted_aes_key))
        decrypted_test_message = decrypt_aes_data(self.aeskey, test_message)

        if not decrypted_test_message.get("text") == "TestEncryptionMessage":
            # ToDo: fix this
            exit("Failed")

        self.encrypted = True

        reversed_fill = decrypted_test_message.get("fill")[::-1]
        msg = {"text": "TestEncryptionMessageResponse", "fill": reversed_fill}
        await self.send_message(self.serialize(msg), expect_reply=False)

    async def get_connection(self):
        """Connects to socket server. Tries a max of 3 times"""
        print(f"Opening connection to {self._address} on port {self._port}")
        retries = 3

        for n in range(retries):
            con = asyncio.open_connection(self._address, self._port)
            try:
                self.reader, self.writer = await asyncio.wait_for(con, timeout=3)

                break

            except asyncio.TimeoutError:
                print(f"Timeout error connecting to {self._address}")
                await asyncio.sleep(n)
            except ConnectionError:
                print(f"Connection error connecting to {self._address}")

    def connected(self) -> bool:
        """If the socket is connected or not"""
        return self._connected

    async def wait_for_message(self) -> bytes:
        # ToDo: bit naff serialing again after decrypting. Fix that up
        """Blocks waiting for a message on the socket until seperator is received"""
        while True:
            # ToDo: make this error handling a bit better. E.g. if authentication fails,
            # this error will get raised instead of letting the client know
            try:
                data = await self.reader.readuntil(separator=self.seperator)
            except asyncio.IncompleteReadError as e:
                exit(repr(e))
            message = data.rstrip(self.seperator)
            if self.encrypted:
                message = decrypt_aes_data(self.aeskey, message)
                message = self.serialize(message)

            return message

    # async def check_encryption_and_send(
    #     self, message: bytes, expect_reply: bool = True
    # ):
    #     """If our state is encrypted, encrypt data and send otherwise just send"""
    #     if self.encrypted:
    #         message = encrypt_aes_data(self.aeskey, message)

    #     encoded = self.serialize(message)
    #     return await self.send_message(encoded, expect_reply)

    async def send_message(self, message: bytes, expect_reply: bool = True):
        """Writes data on the socket"""
        if self.encrypted:
            print("Sending encrypted message")
            message = encrypt_aes_data(self.aeskey, message)
        else:
            print("Sending message in the clear")

        self.writer.write(message + self.seperator)
        await self.writer.drain()
        print("Message sent")

        if expect_reply:
            return await self.wait_for_message()

    async def close_socket(self):
        """Lets other end know we're closed, then closes socket"""
        self.writer.write_eof()
        self.writer.close()
        await self.writer.wait_closed()

    def __del__(self):
        if self.writer and not self.writer.is_closing():
            print("Closing socket")
            self.loop.run_until_complete(self.close_socket())


class EncryptedSocketServerTransport(ServerTransport):
    def __init__(
        self,
        address: str,
        port: int,
        whitelisted_addresses: list = [],
        authenticate_clients: bool = False,
    ):
        self._address = address
        self._port = port
        self.is_async = True
        self.sockets = {}
        self.messages = []
        self.seperator = b"<?!!?>"
        # ToDo: validate addresses
        self.whitelisted_addresses = whitelisted_addresses
        self.authenticate_clients = authenticate_clients

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

        _, encrypted_aes_key = await self.receive_on_socket(peer, reader)

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
        print("Encryption state:", self.sockets[peer]["encrypted"])

    def generate_key_data(self, peer):
        rsa = RSA.generate(2048)
        rsa_private = rsa.export_key()
        rsa_public = rsa.publickey().export_key()
        self.sockets[peer]["key_data"] = {
            "RSAkey": rsa,
            "Private": rsa_private,
            "Public": rsa_public,
        }

    async def authenticated(self, peer_ip) -> bool:
        """Called when connection is established to verify correct source IP"""
        if peer_ip not in self.whitelisted_addresses:
            # Delaying here doesn't really stop against a DoS attack so have lowered
            # this to 3 seconds. In fact, it makes it even easier to DoS as you have an
            # open socket consuming resources / port
            await asyncio.sleep(3)
            print(
                f"Reject Connection, wrong IP: {peer_ip} Expected {self.whitelisted_addresses}"
            )
            return False
        return True

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        print("Peer connected:", peer)

        if self.authenticate_clients and not await self.authenticated(peer[0]):
            writer.close()
            return

        self.sockets[peer] = {
            "encrypted": False,
            "reader": reader,
            "writer": writer,
            "key_data": {},
        }

        await self.encrypt_socket(reader, writer)

        running = True

        while running:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            message = await asyncio.wait_for(task, None)

            if message:
                # print("Message received (decrypted):", message)
                self.messages.append(message)
            else:  # Socket closed
                running = False

    async def start_server(self):
        # ToDo: pass in variables
        self.server = await asyncio.start_server(
            self.handle_client, self._address, self._port, start_serving=True
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        print(f"Serving on {addrs}")

    async def receive_on_socket(self, peer, reader) -> tuple | None:
        if reader.at_eof():
            self.sockets[peer]["writer"].close()
            del self.sockets[peer]
            print("AT EOF")
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
