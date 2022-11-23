from __future__ import annotations  # 3.10 style

import asyncio
from typing import Any, Optional

import bson
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

from aiotinyrpc.log import log
from aiotinyrpc.transports import ClientTransport, ServerTransport
from aiotinyrpc.auth import AuthProvider

import ssl
import tempfile

EOF = "EOF"


async def tls_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_side: bool = False,
):
    """Manually perform a TLS handshake over a stream"""

    if not server_side and not ssl_context:
        ssl_context = ssl.create_default_context()

    transport = writer.transport
    protocol = transport.get_protocol()
    # otherwise we get the following in the logs:
    #   returning true from eof_received() has no effect when using ssl warnings
    protocol._over_ssl = True

    loop = asyncio.get_event_loop()

    new_transport = await loop.start_tls(
        transport=transport,
        protocol=protocol,
        sslcontext=ssl_context,
        server_side=server_side,
    )

    reader._transport = new_transport
    writer._transport = new_transport


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


def decrypt_aes_data(key, data: bytes) -> dict:
    """Take a bytes stream and AES key and decrypt it"""
    # ToDo: Error checking
    try:
        jdata = bson.decode(data)
        nonce = bytes.fromhex(jdata["nonce"])
        tag = bytes.fromhex(jdata["tag"])
        ciphertext = bytes.fromhex(jdata["ciphertext"])
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        msg = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise
    log.debug(msg)
    return bson.decode(msg)


def serialize(msg: Any) -> bytes:
    """Converts any object to json and encodes in as bytes, reading for sending"""
    return bson.encode(msg)


def deserialize(msg: bytes) -> Any:
    return bson.decode(msg)


class EncryptedSocketClientTransport(ClientTransport):
    """ToDo: this docstring"""

    def __init__(
        self,
        address: str,
        port: int,
        debug: bool = False,
        auth_provider: AuthProvider | None = None,
        proxy_target: str = "",
        proxy_port: str = "",
        proxy_ssl: bool = False,
        cert: bytes = b"",
        key: bytes = b"",
        ca: bytes = b"",
    ):
        self._address = address
        self._port = port
        self._connected = False
        self.debug = debug
        self.is_async = True
        self.encrypted = False
        self.separator = b"<?!!?>"
        self.loop = asyncio.get_event_loop()
        self.reader, self.writer = None, None
        self.auth_provider = auth_provider
        self.proxy_target = proxy_target
        self.proxy_port = proxy_port
        self.proxy_ssl = proxy_ssl
        self.cert = cert
        self.key = key
        self.ca = ca

        # Removed this... up to the client how they want to proceed
        # self.connect()

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

    async def setup_forwarding(self):
        msg = {"proxy_required": False, "proxy_target": ""}
        if self.proxy_target:
            msg["proxy_required"] = True
            msg["proxy_target"] = self.proxy_target
            msg["proxy_port"] = self.proxy_port
            msg["proxy_ssl"] = self.proxy_ssl

        resp = await self.send_message(serialize(msg))
        resp = deserialize(resp).get("response")

        if resp and self.proxy_target:  # from this point we are being proxied
            if self.proxy_ssl:
                await self.upgrade_socket()
            if self.auth_provider and resp:
                authenticated = await self.authenticate()
                if not authenticated:
                    return False
                log.info("Proxy Connection authenticated!")
                msg = {"proxy_required": False, "proxy_target": ""}
                resp = await self.send_message(serialize(msg))

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
        # ToDo: log this
        if rsa_public_key == EOF:
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False
            return

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

        test_message = await self.send_message(serialize(encrypted_aes_key))
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
        await self.send_message(serialize(msg), expect_reply=False)

    async def authenticate(self):
        challenge = await self.wait_for_message()
        if challenge == EOF:
            return False

        try:
            challenge = deserialize(challenge)
        except bson.errors.InvalidBSON:
            log.error("Invalid authenticate message received")
            return False

        msg = challenge.get("to_sign")
        try:
            auth_message = self.auth_provider.auth_message(msg)
        except ValueError:
            log.error("Malformed private key... you need to reset key")
            return False

        res = await self.send_message(serialize(auth_message))
        res = deserialize(res)
        return res.get("authenticated", False)

    async def connect(self):
        await self._connect()

        if not self.reader and not self.writer:
            return

        if self.auth_provider:
            authenticated = await self.authenticate()
            if not authenticated:
                return
            log.info("Connection authenticated!")

        self._connected = True

        await self.setup_forwarding()

        await self.setup_encryption()

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
        """Blocks waiting for a message on the socket until separator is received"""
        # ToDo: make this error handling a bit better. E.g. if authentication fails,
        # this error will get raised instead of letting the client know
        try:
            data = await self.reader.readuntil(separator=self.separator)
        except asyncio.IncompleteReadError as e:
            log.error("EOF reached, socket closed")
            self._connected = False
            self.encrypted = False
            return EOF

        message = data.rstrip(self.separator)
        if self.encrypted:
            message = decrypt_aes_data(self.aeskey, message)
            log.debug(f"Received message (decoded): {message}")
            message = serialize(message)

        return message

    async def upgrade_socket(self):
        cert = tempfile.NamedTemporaryFile()
        with open(cert.name, "wb") as f:
            f.write(self.cert)
        key = tempfile.NamedTemporaryFile()
        with open(key.name, "wb") as f:
            f.write(self.key)
        ca = tempfile.NamedTemporaryFile()
        with open(ca.name, "wb") as f:
            f.write(self.ca)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_cert_chain(cert.name, keyfile=key.name)
        context.load_verify_locations(cafile=ca.name)
        context.check_hostname = False
        context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
        context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")

        await tls_handshake(
            reader=self.reader,
            writer=self.writer,
            ssl_context=context,
        )

    async def send_message(self, message: bytes, expect_reply: bool = True):
        """Writes data on the socket"""
        if self.encrypted:
            log.debug(f"Sending encrypted message (decoded): {bson.decode(message)}")
            message = encrypt_aes_data(self.aeskey, message)
        else:
            log.debug(f"Sending message in the clear (decoded): {bson.decode(message)}")

        self.writer.write(message + self.separator)
        await self.writer.drain()
        log.debug("Message sent!")

        if expect_reply:
            return await self.wait_for_message()

    async def disconnect(self):
        self._connected = False
        self.encrypted = False
        await self._close_socket()

    async def _close_socket(self):
        """Lets other end know we're closed, then closes socket"""
        if self.writer and not self.writer.is_closing():
            try:
                self.writer.write_eof()
                pass
            except NotImplementedError:
                # ssl doesn't have half open connections
                pass
            self.writer.close()
            await self.writer.wait_closed()
        self.reader = None
        self.writer = None


class EncryptedSocketServerTransport(ServerTransport):
    def __init__(
        self,
        address: str,
        port: int,
        whitelisted_addresses: list = [],
        verify_source_address: bool = True,
        auth_provider: AuthProvider | None = None,
        ssl: ssl.SSLContext | None = None,
        debug: bool = False,
    ):
        self._address = address
        self._port = port
        self.is_async = True
        self.debug = debug
        self.sockets = {}
        self.messages = []
        self.separator = b"<?!!?>"
        # ToDo: validate addresses
        self.whitelisted_addresses = whitelisted_addresses
        self.verify_source_address = verify_source_address
        self.auth_provider = auth_provider
        self.ssl = ssl

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
            del self.sockets[peer]
            return

        # ToDo: try / except
        aeskey = self.decrypt_aes_key(
            self.sockets[peer]["key_data"]["Private"], bson.decode(encrypted_aes_key)
        )
        self.sockets[peer]["key_data"]["AESKEY"] = aeskey

        # Send a test encryption request, always include random data
        random = get_random_bytes(16).hex()
        test_msg = {"text": "TestEncryptionMessage", "fill": random}

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
        await self.send(writer, serialize(challenge))

        try:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            _, challenge_reply = await asyncio.wait_for(task, timeout=10)

        except (TypeError, asyncio.TimeoutError):
            log.warn("Malformed (or no) challenge reply... dropping")
            writer.close()
            await writer.wait_closed()
            del self.sockets[peer]
            return False

        challenge_reply = deserialize(challenge_reply)
        authenticated = self.auth_provider.verify_auth(challenge_reply)
        await self.send(writer, serialize(self.auth_provider.auth_reply_message()))
        log.info(f"Auth provider authenticated: {authenticated}")
        if not authenticated:
            # ToDo: check this actually closes socket
            writer.close()
            await writer.wait_closed()
            del self.sockets[peer]
            return False
        return True

    async def process_forwarding_messages(self, peer, reader, writer):
        try:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            _, forwarding = await asyncio.wait_for(task, timeout=10)

        except (TypeError, asyncio.TimeoutError):
            log.warn("Malformed (or no) forwarding request... dropping")
            writer.close()
            await writer.wait_closed()
            return False

        forwarding = deserialize(forwarding)
        proxy_required = forwarding.get("proxy_required")
        proxy_target = forwarding.get("proxy_target")
        proxy_port = forwarding.get("proxy_port")
        proxy_ssl = forwarding.get("proxy_ssl")

        if proxy_required:
            return (proxy_target, proxy_port)
        else:
            return (False, False)

    async def setup_forwarding(self, host, port, local_reader, local_writer):
        """Connects to socket server. Tries a max of 3 times"""
        log.info(f"Proxying connection to {host} on port {port}")
        retries = 3

        proxy_reader = proxy_writer = None
        for n in range(retries):
            con = asyncio.open_connection(host, port)
            try:
                proxy_reader, proxy_writer = await asyncio.wait_for(con, timeout=3)

                break

            except asyncio.TimeoutError:
                log.warn(f"Timeout error connecting to {host}")
            except ConnectionError:
                log.warn(f"Connection error connecting to {host}")
            await asyncio.sleep(n)

        if proxy_writer:
            pipe1 = self.pipe(local_reader, proxy_writer)
            pipe2 = self.pipe(proxy_reader, local_writer)

            asyncio.create_task(pipe1)
            asyncio.create_task(pipe2)
            return True
        return False

    async def pipe(self, reader, writer):
        # ToDo: suspect this isn't closing writer facing keeper (local_writer)
        try:
            while not reader.at_eof():
                writer.write(await reader.read(2048))
        finally:
            writer.close()
            await writer.wait_closed()

    # async def upgrade_socket(self, peer, local_cert, local_key, ca_cert):
    #     reader = self.sockets[peer]["reader"]
    #     writer = self.sockets[peer]["writer"]

    #     context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    #     context.load_cert_chain(local_cert, keyfile=local_key)
    #     context.load_verify_locations(cafile=ca_cert)
    #     context.check_hostname = False
    #     context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    #     # ToDo: check these
    #     context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")

    #     await tls_handshake(
    #         reader=reader,
    #         writer=writer,
    #         ssl_context=context,
    #         server_side=True,
    #     )

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        log.info(f"Peer connected: {peer}")

        if self.verify_source_address and not await self.valid_source_ip(peer[0]):
            log.warn("Source IP address not verified... dropping")
            writer.close()
            await writer.wait_closed()
            return

        self.sockets[peer] = {
            "encrypted": False,
            "reader": reader,
            "writer": writer,
            "key_data": {},
        }

        authenticated = True
        if self.auth_provider:
            # This closes the socket if not authenticated
            authenticated = await self.authenticate(peer, reader, writer)

        if not authenticated:
            return

        # ToDo: this need quite a bit of work
        host, port = await self.process_forwarding_messages(peer, reader, writer)
        if host:
            connected = await self.setup_forwarding(host, port, reader, writer)
            await self.send(writer, serialize({"response": connected}))

            if not connected:
                writer.close()
                await writer.wait_closed()
                del self.sockets[peer]
            return
        else:
            await self.send(writer, serialize({"response": False}))
            await self.encrypt_socket(reader, writer)

        running = True

        while running:
            message = await asyncio.wait_for(self.receive_on_socket(peer, reader), None)

            if message:
                log.debug(
                    f"Message received (decrypted and decoded): {bson.decode(message[1])})"
                )
                self.messages.append(message)
            else:  # Socket closed
                writer.close()
                await writer.wait_closed()
                del self.sockets[peer]
                running = False

    async def stop_server(self):
        for peer in self.sockets.copy():
            self.sockets[peer]["writer"].close()
            await self.sockets[peer]["writer"].wait_closed()
            del self.sockets[peer]

        self.server.close()
        await self.server.wait_closed()

    async def start_server(self):
        started = False
        while not started:
            try:
                self.server = await asyncio.start_server(
                    self.handle_client,
                    self._address,
                    self._port,
                    ssl=self.ssl,
                    start_serving=True,
                )
                started = True
            except OSError as e:
                log.error(f"({e})... retrying in 5 seconds")
                await asyncio.sleep(5)

        addrs = ", ".join(str(sock.getsockname()) for sock in self.server.sockets)
        log.info(f"Serving on {addrs}")

    async def receive_on_socket(self, peer, reader) -> tuple | None:
        # ToDo: does this ever happen?
        if reader.at_eof():
            log.info(f"Remote peer {peer} sent EOF, closing socket")
            self.sockets[peer]["writer"].close()
            await self.sockets[peer]["writer"].wait_closed()
            del self.sockets[peer]
            return None
        try:
            data = await reader.readuntil(separator=self.separator)
        except asyncio.exceptions.IncompleteReadError:
            return None
        except asyncio.LimitOverrunError as e:
            data = []
            while True:
                current = await reader.read(64000)
                if current.endswith(self.separator):
                    data.append(current)
                    break
                data.append(current)
            data = b"".join(data)

        message = data.rstrip(self.separator)

        if self.sockets[peer]["encrypted"]:
            message = decrypt_aes_data(
                self.sockets[peer]["key_data"]["AESKEY"], message
            )
            message = bson.encode(message)

        return (peer, message)

    # receive message and send_reply are the external functions called by the RPC server
    async def receive_message(self) -> tuple:
        while not self.messages:
            # ToDo: Set this via param, debug 0.5, prod 0.05
            await asyncio.sleep(0.05)

        addr, message = self.messages.pop(0)
        return addr, message

    async def send(self, writer, reply):
        writer.write(reply + self.separator)
        await writer.drain()

    async def send_reply(self, context: tuple, reply: bytes):
        if self.sockets[context]["encrypted"]:
            reply = encrypt_aes_data(self.sockets[context]["key_data"]["AESKEY"], reply)

        writer = self.sockets[context]["writer"]
        await self.send(writer, reply)
