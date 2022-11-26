from __future__ import annotations  # 3.10 style

import asyncio
from typing import Optional

import bson
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

from aiotinyrpc.log import log
from aiotinyrpc.transports import ClientTransport, ServerTransport

from aiotinyrpc.transports.socketmessages import (
    RsaPublicKeyMessage,
    SessionKeyMessage,
    AesKeyMessage,
    SerializedMessage,
    ErrorMessage,
    Message,
    TestMessage,
    ProxyMessage,
    ProxyResponseMessage,
    RpcReplyMessage,
    RpcRequestMessage,
)
from aiotinyrpc.auth import AuthProvider

import ssl
import tempfile

from dataclasses import dataclass


@dataclass
class KeyData:
    rsa_key: str = ""
    aes_key: str = ""
    private: str = ""
    public: str = ""


@dataclass
class EncryptedSocket:
    writer: asyncio.StreamWriter
    reader: asyncio.StreamReader
    key_data: KeyData = KeyData()
    encrypted: bool = False


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

        # ToDo: maybe have a alway connected flag and if set, we connect here
        # self.connect()

    @staticmethod
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

    @property
    def connected(self) -> bool:
        """If the socket is connected or not"""
        return self._connected

    def session_key_message(self, key_pem: str, aes_key: str) -> SessionKeyMessage:
        """Generate and encrypt AES session key with RSA public key"""
        key = RSA.import_key(key_pem)
        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(key)
        rsa_enc_session_key = cipher_rsa.encrypt(session_key)
        msg = AesKeyMessage(aes_key)
        encypted_aes_msg = msg.encrypt(session_key)

        return SessionKeyMessage(encypted_aes_msg.serialize(), rsa_enc_session_key)

    async def setup_forwarding(self):
        # ToDo: is the bool necessary?
        msg = ProxyMessage(
            bool(self.proxy_target), self.proxy_target, self.proxy_port, self.proxy_ssl
        )

        data = await self.send_message(msg)
        forwarding_active = data.response

        # ToDo: need to deal with error situation if proxy target and not active
        if (
            forwarding_active and self.proxy_target
        ):  # from this point we are being proxied
            if self.proxy_ssl:
                await self.upgrade_socket()
            if self.auth_provider:
                authenticated = await self.authenticate()
                if not authenticated:
                    return False
                log.info("Proxy Connection authenticated!")
                msg = ProxyMessage()
                # We are telling the target we don't need proxy
                resp = await self.send_message(msg)

    async def setup_encryption(self):
        """Once the socket is connected, the encryption process begins.
        1/ Server sends RSA public key
        2/ Client creates an AES session key and encrypts it with public RSA key
        3/ Server decrypts AES session key and uses it to generate an encrypted test message
        4/ Client decrypts AES message, reverses the random data and sends it back
        5/ Link is now confirmed by both ends to be encrypted
        6/ Encrypted flag is set - any further messages will be AES protected"""

        # ToDo: maybe get the other end to return a useful message here if authentication failed
        msg = await self.wait_for_message()
        # ToDo: log this
        if isinstance(msg, ErrorMessage):
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False
            return

        rsa_public_key = msg.key.decode("utf-8")
        self.aeskey = get_random_bytes(16).hex().encode("utf-8")
        try:
            session_key_message = self.session_key_message(rsa_public_key, self.aeskey)
        except ValueError:
            # ToDo: move this to received message
            log.error("Malformed (or no) RSA key received... skipping")
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False
            return

        test_message = await self.send_message(session_key_message)
        if isinstance(msg, ErrorMessage):
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False
            return

        decrypted_test_message = test_message.decrypt(self.aeskey)

        if not decrypted_test_message.text == "TestEncryptionMessage":
            log.error("Malformed test aes message received... skipping")
            self.writer.close()
            await self.writer.wait_closed()
            self._connected = False
            return

        self.encrypted = True

        reversed_fill = decrypted_test_message.fill[::-1]
        msg = TestMessage(reversed_fill, "TestEncryptionMessageResponse")
        await self.send_message(msg, expect_reply=False)

    async def authenticate(self):
        challenge = await self.wait_for_message()

        if isinstance(challenge, ErrorMessage):
            return False

        try:
            auth_message = self.auth_provider.auth_message(challenge.to_sign)
        except ValueError:
            log.error("Malformed private key... you need to reset key")
            return False

        res = await self.send_message(auth_message)
        return res.authenticated

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
            return ErrorMessage("EOF reached... socket closed")

        data = data.rstrip(self.separator)
        # ToDo: catch
        message = SerializedMessage(data).deserialize()

        if self.encrypted:
            message = message.decrypt(self.aeskey)
            log.debug(f"Received message (decrypted): {message}")

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

        await self.tls_handshake(
            reader=self.reader,
            writer=self.writer,
            ssl_context=context,
        )

    # ToDo: this interface is a bit murky. Called both internally and externally
    # Need to split these so this is only called externally
    async def send_message(
        self, message: Message | bytes, expect_reply: bool = True
    ) -> Message | None:
        """Writes data on the socket"""
        # from upper RPC layer
        if isinstance(message, bytes):
            # should always be encrypted here?
            message = RpcRequestMessage(message)
        if self.encrypted:
            log.debug(f"Sending encrypted message: {message}")
            message = message.encrypt(self.aeskey)
        else:
            log.debug(f"Sending message in the clear: {message}")

        self.writer.write(message.serialize() + self.separator)
        await self.writer.drain()
        log.debug("Message sent!")

        if expect_reply:
            res = await self.wait_for_message()
            if isinstance(res, RpcReplyMessage):
                res = res.msg
            return res

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

    def parse_session_key_message(self, key_pem: str, msg: SessionKeyMessage) -> str:
        """Used by Node to decrypt and return the AES Session key using the RSA Key"""
        private_key = RSA.import_key(key_pem)

        enc_session_key = msg.rsa_encrypted_session_key

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        enc_aes_key_message = SerializedMessage(msg.aes_key_message).deserialize()

        aes_key_message = enc_aes_key_message.decrypt(session_key)
        return aes_key_message.aes_key

    async def encrypt_socket(self, reader, writer):
        peer = writer.get_extra_info("peername")
        self.generate_key_data(peer)

        msg = RsaPublicKeyMessage(self.sockets[peer].key_data.public)
        # ToDo: does receive_on_socket need to return peer?
        await self.send(writer, msg.serialize())

        try:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            _, session_key_message = await asyncio.wait_for(task, timeout=10)

        except (TypeError, asyncio.TimeoutError):
            log.error("Incorrect (or no) encryption message received... dropping")
            writer.close()
            await writer.wait_closed()
            del self.sockets[peer]
            return

        if isinstance(session_key_message, ErrorMessage):
            log.error(f"Encrypt socket error: {session_key_message.error}")
            writer.close()
            await writer.wait_closed()
            del self.sockets[peer]
            return

        # ToDo: try / except
        aes_key = self.parse_session_key_message(
            self.sockets[peer].key_data.private, session_key_message
        )

        self.sockets[peer].key_data.aes_key = aes_key

        # Send a test encryption request, always include random data
        random = get_random_bytes(16).hex()
        test_msg = TestMessage(random)
        encrypted_test_msg = test_msg.encrypt(aes_key)

        await self.send(writer, encrypted_test_msg.serialize())
        _, res = await self.receive_on_socket(peer, reader)
        response = res.decrypt(aes_key)

        if (
            response.text == "TestEncryptionMessageResponse"
            and response.fill == random[::-1]
        ):
            self.sockets[peer].encrypted = True
        log.info(f"Socket is encrypted: {self.sockets[peer].encrypted}")

    def generate_key_data(self, peer):
        rsa = RSA.generate(2048)
        rsa_private = rsa.export_key()
        rsa_public = rsa.publickey().export_key()
        self.sockets[peer].key_data.rsa_key = rsa
        self.sockets[peer].key_data.private = rsa_private
        self.sockets[peer].key_data.public = rsa_public

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
        challenge_msg = self.auth_provider.challenge_message()
        await self.send(writer, challenge_msg.serialize())

        try:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            _, challenge_reply_msg = await asyncio.wait_for(task, timeout=10)

        except (TypeError, asyncio.TimeoutError):
            log.warn("Malformed (or no) challenge reply... dropping")
            writer.close()
            await writer.wait_closed()
            del self.sockets[peer]
            return False

        authenticated = self.auth_provider.verify_auth(challenge_reply_msg)
        reply_message = self.auth_provider.auth_reply_message()

        await self.send(writer, reply_message.serialize())
        log.info(f"Auth provider authenticated: {authenticated}")
        if not authenticated:
            # ToDo: check this actually closes socket
            writer.close()
            await writer.wait_closed()
            del self.sockets[peer]
            return False
        return True

    async def process_forwarding_message(self, peer, reader, writer):
        try:
            task = asyncio.create_task(self.receive_on_socket(peer, reader))
            _, forwarding_msg = await asyncio.wait_for(task, timeout=10)

        except (TypeError, asyncio.TimeoutError):
            log.warn("Malformed (or no) forwarding request... dropping")
            writer.close()
            await writer.wait_closed()
            return False

        proxy_target = forwarding_msg.proxy_target
        proxy_port = forwarding_msg.proxy_port
        # proxy_ssl = forwarding_msg.proxy_ssl

        if forwarding_msg.proxy_required:
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

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info("peername")
        log.info(f"Peer connected: {peer}")

        if self.verify_source_address and not await self.valid_source_ip(peer[0]):
            log.warn("Source IP address not verified... dropping")
            writer.close()
            await writer.wait_closed()
            return

        self.sockets[peer] = EncryptedSocket(writer, reader)

        authenticated = True
        if self.auth_provider:
            # This closes the socket if not authenticated
            authenticated = await self.authenticate(peer, reader, writer)

        if not authenticated:
            return

        msg = ProxyResponseMessage(False)

        host, port = await self.process_forwarding_message(peer, reader, writer)
        if host:  # forwarding required
            success = await self.setup_forwarding(host, port, reader, writer)
            msg.response = success
            await self.send(writer, msg.serialize())

            if not success:
                writer.close()
                await writer.wait_closed()
                del self.sockets[peer]
            return
        # need to respond here, it doesn't really mean the same thing though
        await self.send(writer, msg.serialize())
        await self.encrypt_socket(reader, writer)

        while True:
            message = await asyncio.wait_for(self.receive_on_socket(peer, reader), None)
            # ToDo: fix this up
            # At this point, the only thing we should be receiving are ErrorMessages, or a
            # tuple of context and RpcRequestMessage.
            if isinstance(message, ErrorMessage):
                # Socket closed
                writer.close()
                await writer.wait_closed()
                del self.sockets[peer]
                break

            log.debug(
                f"Message received (decrypted and decoded): {bson.decode(message[1].msg)})"
            )
            # ToDo: message[1] is RpcRequestMessage, tidy this up a bit
            self.messages.append((message[0], message[1].msg))

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
            # This probably shouldn't happen yeah?
            log.info(f"Remote peer {peer} sent EOF, closing socket")
            self.sockets[peer].writer.close()
            await self.sockets[peer].writer.wait_closed()
            del self.sockets[peer]
            return ErrorMessage("Reader is at EOF")
        try:
            data = await reader.readuntil(separator=self.separator)
        except asyncio.exceptions.IncompleteReadError:
            return ErrorMessage("Reader is at EOF")
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
        # ToDO: catch
        message = SerializedMessage(message).deserialize()
        if self.sockets[peer].encrypted:
            message = message.decrypt(self.sockets[peer].key_data.aes_key)
        return (peer, message)

    # receive message and send_reply are the external functions called by the RPC server
    async def receive_message(self) -> tuple:
        while not self.messages:
            # ToDo: Set this via param, debug 0.5, prod 0.05
            await asyncio.sleep(0.05)

        addr, message = self.messages.pop(0)
        # message = message.as_dict()
        return addr, message

    async def send(self, writer: asyncio.StreamWriter, msg: bytes):
        writer.write(msg + self.separator)
        await writer.drain()

    async def send_reply(self, context: tuple, data: bytes):
        msg = RpcReplyMessage(data)
        # this should always be True
        if self.sockets[context].encrypted:
            msg = msg.encrypt(self.sockets[context].key_data.aes_key)

        await self.send(self.sockets[context].writer, msg.serialize())
