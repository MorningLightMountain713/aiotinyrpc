from __future__ import annotations
from typing import Callable, Optional

import asyncio
import re

from fluxrpc.transports import ClientTransport

from fluxrpc.transports.socket.messages import (
    RsaPublicKeyMessage,
    SessionKeyMessage,
    AesKeyMessage,
    SerializedMessage,
    EncryptedMessage,
    Message,
    TestMessage,
    ChallengeReplyMessage,
    ProxyMessage,
    ProxyResponseMessage,
    RpcReplyMessage,
    RpcRequestMessage,
    PtyMessage,
    PtyResizeMessage,
    PtyClosedMessage,
)


import ssl
import tempfile


from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

from fluxrpc.log import log

from fluxrpc.auth import (
    AuthProvider,
    ChallengeMessage,
    AuthReplyMessage,
)

from .symbols import (
    AUTH_DENIED,
    PROXY_AUTH_DENIED,
    AUTH_ADDRESS_REQUIRED,
    PROXY_AUTH_ADDRESS_REQUIRED,
    NO_SOCKET,
)


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
        on_pty_data_callback: Callable | None = None,
        on_pty_closed_callback: Callable | None = None,
    ):
        self._address = address
        self.auth_required = True
        self.auth_address = ""
        self.proxy_auth_address = ""
        self.failed_on = ""
        self._port = port
        self._connected = False
        self._connecting = False
        self._disconnecting = False
        self.debug = debug
        self.is_async = True
        self.encrypted = False
        self.authenticated = False
        self.proxy_authenticated = False
        self.separator = b"<?!!?>"
        self.messages = asyncio.Queue()
        self.loop = asyncio.get_event_loop()
        self.reader, self.writer = None, None
        self.auth_provider = auth_provider
        self.proxy_auth_required = True
        self.proxy_target = proxy_target
        self.proxy_port = proxy_port
        self.proxy_ssl = proxy_ssl
        self.cert = cert
        self.key = key
        self.ca = ca
        self.on_pty_data_callback = on_pty_data_callback
        self.on_pty_closed_callback = on_pty_closed_callback
        self.encrypted_event = asyncio.Event()
        self.forwarding_event = asyncio.Event()
        self.authentication_event = asyncio.Event()
        self.challenge_complete_event = asyncio.Event()
        self.channels = 0
        self._proxy_source = ()

        # ToDo: maybe have a alway connected flag and if set, we connect here
        # self.connect()

    @property
    def connected(self) -> bool:
        """If the socket is connected or not"""
        return self._connected

    @property
    def connecting(self) -> bool:
        return self._connecting

    @property
    def address(self) -> str:
        return self._address

    @property
    def proxy_source(self) -> tuple:
        return self._proxy_source

    @staticmethod
    def session_key_message(key_pem: str, aes_key: str) -> SessionKeyMessage:
        """Generate and encrypt AES session key with RSA public key"""
        key = RSA.import_key(key_pem)
        session_key = get_random_bytes(16)
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(key)
        rsa_enc_session_key = cipher_rsa.encrypt(session_key)
        msg = AesKeyMessage(aes_key)
        encypted_aes_msg = msg.encrypt(session_key)

        return SessionKeyMessage(encypted_aes_msg.serialize(), rsa_enc_session_key)

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

    ## handlers

    async def authentication_message_handler(self, msg):
        if isinstance(msg, ChallengeMessage):
            proxied = msg.source == [self.proxy_target, self.proxy_port]
            if not msg.auth_required:
                if not proxied:
                    self.auth_required = False
                else:
                    self.proxy_auth_required = False

                # this cancels the timer on remote end
                auth_message = ChallengeReplyMessage()
                await self.send(auth_message.serialize())
                self.challenge_complete_event.set()
                return

            # auth required

            if not self.auth_provider:
                if not proxied:
                    self.failed_on = AUTH_ADDRESS_REQUIRED
                    self.auth_address = msg.address
                else:
                    self.failed_on = PROXY_AUTH_ADDRESS_REQUIRED
                    self.proxy_auth_address = msg.address
                # this saves the remote end timing out
                auth_message = ChallengeReplyMessage(close_connection=True)
                await self.send(auth_message.serialize())
                self.challenge_complete_event.set()
                return

            try:
                auth_message = self.auth_provider.auth_message(msg.id, msg.to_sign)
            except ValueError:
                log.error("Malformed private key... you need to reset key")
                self.challenge_complete_event.set()
                return

            await self.send(auth_message.serialize())
            self.challenge_complete_event.set()

        if isinstance(msg, AuthReplyMessage):
            proxied = msg.source == [self.proxy_target, self.proxy_port]

            if not proxied:
                self.authenticated = msg.authenticated
                if not self.authenticated:
                    self.failed_on = AUTH_DENIED
            else:
                self.proxy_authenticated = msg.authenticated
                if not self.proxy_authenticated:
                    self.failed_on = PROXY_AUTH_DENIED

            self.authentication_event.set()

    async def forwarding_message_handler(self, msg):
        # ProxyResponseMessage
        if msg.success and self.proxy_target:
            # from this point we are being proxied
            self._proxy_source = msg.socket_details
            if self.proxy_ssl:
                await self.upgrade_socket()

            await self.challenge_complete_event.wait()
            self.challenge_complete_event.clear()

            if self.proxy_auth_required and not self.auth_provider:
                self.auth_error = "Auth required and no auth provider set"
                log.error(self.auth_error)
                return

            if self.proxy_auth_required:
                await self.authentication_event.wait()
                self.authentication_event.clear()

                if not self.proxy_authenticated:
                    log.error("Proxy authentication error")
                    return

                log.info("Proxy Connection authenticated!")
            resp = ProxyMessage()
            # We are telling the target we don't need proxy
            await self.send(resp.serialize())
        self.forwarding_event.set()

    async def encryption_message_handler(self, msg):
        if isinstance(msg, RsaPublicKeyMessage):
            rsa_public_key = msg.key.decode("utf-8")

            self.aeskey = get_random_bytes(16).hex().encode("utf-8")
            try:
                session_key_message = self.session_key_message(
                    rsa_public_key, self.aeskey
                )
            except ValueError:
                # ToDo: move this to received message
                log.error("Malformed (or no) RSA key received... skipping")
                self.writer.close()
                await self.writer.wait_closed()
                self._connected = False
                return

            await self.send(session_key_message.serialize())

        if isinstance(msg, EncryptedMessage):
            decrypted_test_message = msg.decrypt(self.aeskey)

            if not decrypted_test_message.text == "TestEncryptionMessage":
                log.error("Malformed test aes message received... skipping")
                self.writer.close()
                await self.writer.wait_closed()
                self._connected = False
                return

            self.encrypted = True
            # asyncio event

            reversed_fill = decrypted_test_message.fill[::-1]
            msg = TestMessage(reversed_fill, "TestEncryptionMessageResponse")
            msg = msg.encrypt(self.aeskey)
            await self.send(msg.serialize())
            self.encrypted_event.set()

    ## setup

    async def send_forwarding_message(self):
        # ToDo: is the bool necessary?
        msg = ProxyMessage(
            bool(self.proxy_target),
            self.proxy_target,
            self.proxy_port,
            self.proxy_ssl,
        )

        await self.send(msg.serialize())

    # async def wait_for_auth_reply(self):
    #     auth_response = await self.messages.get()
    #     if not isinstance(auth_response, AuthReplyMessage):
    #         raise ValueError("Wrong message type received for authentication")
    #     return auth_response.authenticated

    async def connect(self):
        log.info(f"Transport id: {id(self)} Connecting...")
        if self._connecting:
            log.info("Connecting... adding channel")
            self.channels += 1

        while self._connecting or self._disconnecting:
            await asyncio.sleep(0.01)

        if self.channels:
            self.channels += 1
            log.info(f"Adding new channel. Total: {self.channels}")
            return

        self._connecting = True
        await self._connect()

        if not self.reader and not self.writer:
            self._connecting = False
            self.failed_on = NO_SOCKET
            log.error("No reader or writer... Error connecting")
            return

        asyncio.create_task(self.read_socket_loop())

        await self.challenge_complete_event.wait()
        self.challenge_complete_event.clear()

        self.channels += 1

        if self.auth_required and not self.auth_provider:
            self.auth_error = "Auth required and no auth provider set"
            log.error(self.auth_error)
            await self.disconnect()
            self._connecting = False
            return

        if self.auth_required:
            await self.authentication_event.wait()
            self.authentication_event.clear()

            if not self.authenticated:
                log.error("Authentication error")
                await self.disconnect()
                self._connecting = False
                return

            log.info("Connection authenticated!")

        await self.send_forwarding_message()

        await self.forwarding_event.wait()
        self.forwarding_event.clear()

        await self.encrypted_event.wait()
        self.encrypted_event.clear()

        # self.channels += 1
        log.debug(f"Connection encrypted Total channels: {self.channels}")
        self._connected = True
        self._connecting = False

    async def _connect(self):
        """Connects to socket server. Tries a max of 3 times"""
        log.info(f"Opening connection to {self._address} on port {self._port}")
        retries = 3

        for n in range(retries):
            con = asyncio.open_connection(self._address, self._port)
            try:
                self.reader, self.writer = await asyncio.wait_for(con, timeout=3)
            except asyncio.TimeoutError:
                log.warn(f"Timeout error connecting to {self._address}")
            except ConnectionError:
                log.warn(f"Connection error connecting to {self._address}")
            else:
                break
            await asyncio.sleep(n)

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
        # context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384")

        await self.tls_handshake(
            reader=self.reader,
            writer=self.writer,
            ssl_context=context,
        )

    async def read_socket_loop(self):
        extra_messages = []
        while self.reader and not self.reader.at_eof():
            try:
                data = await self.reader.readuntil(self.separator)
            except asyncio.IncompleteReadError as e:
                log.debug("EOF reached, socket closed")
                self._connected = False
                self.encrypted = False
                break
            except ssl.SSLError as e:
                log.error(e)
                self._connected = False
                self.encrypted = False
                break
            except asyncio.LimitOverrunError as e:
                print("LIMIT OVERRUN!!!!")
                data = []
                
                while True:
                    current = await self.reader.read(64000)
                    if current.endswith(self.separator):
                        data.append(current)
                        break

                    data.append(current)
                
                count = re.findall(b"\<\?!!\?\\>", data[-1])

                # split messages
                if len(count) > 1:
                    multi_message_bytes = data.pop()
                    extra_messages = multi_message_bytes.split(b"<?!!?>")
                    # or just remove the last item?
                    extra_messages = list(filter(None, extra_messages))
                    last_data = extra_messages.pop(0)
                    data.append(last_data+b"<?!!?>")

                data = b"".join(data)
            except Exception as e:
                print("in read socket loop")
                print(repr(e))

            message = data.rstrip(self.separator)

            all_messages = [message, *extra_messages]
            extra_messages = []
            
            for message in all_messages:
                # ToDo: catch
                try:
                    message = SerializedMessage(message).deserialize()
                except Exception as e:
                    print("can't deserialize in for")
                    print(repr(e))
                log.debug(f"Received : {type(message).__name__}")

                if self.encrypted:
                    message = message.decrypt(self.aeskey)

                if isinstance(message, PtyMessage):
                    our_socket = self.writer.get_extra_info("sockname")
                    await self.on_pty_data_callback(our_socket, message.data)
                    continue

                if isinstance(message, RpcReplyMessage):
                    await self.messages.put(message)
                    continue

                if isinstance(message, (ChallengeMessage, AuthReplyMessage)):
                    await self.authentication_message_handler(message)
                    continue

                if isinstance(message, ProxyResponseMessage):
                    asyncio.create_task(self.forwarding_message_handler(message))
                    continue

                if isinstance(message, (RsaPublicKeyMessage, TestMessage)):
                    await self.encryption_message_handler(message)
                    continue

                # This is our test message as we're not encrypted yet
                # it could be part of the handler above but more clear here
                if isinstance(message, EncryptedMessage):
                    await self.encryption_message_handler(message)
                    continue

                if isinstance(message, PtyClosedMessage):
                    our_socket = self.writer.get_extra_info("sockname")
                    await self.on_pty_closed_callback(our_socket)
                    continue

                else:
                    log.error(f"Unknown message: {message}")

        log.debug("Finished read socket loop")

    async def send_pty_message(self, data):
        msg = PtyMessage(data)
        if self.encrypted:
            msg = msg.encrypt(self.aeskey)

        self.writer.write(msg.serialize() + self.separator)
        await self.writer.drain()

    async def send_pty_resize_message(self, rows, cols):
        msg = PtyResizeMessage(rows, cols)
        if self.encrypted:
            msg = msg.encrypt(self.aeskey)

        self.writer.write(msg.serialize() + self.separator)
        await self.writer.drain()

    # ToDo: this interface is a bit murky. Called both internally and externally
    # Need to split these so this is only called externally

    async def send(self, data: bytes):
        self.writer.write(data + self.separator)
        await self.writer.drain()

    async def send_message(
        self,
        message: Message | bytes,
        expect_reply: bool = True,
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

        await self.send(message.serialize())

        if expect_reply:
            res = await self.messages.get()

            if isinstance(res, RpcReplyMessage):
                res = res.payload
            else:
                log.error(f"Waiting for RPC message but received something else: {res}")
            return res

    def reset_state(self):
        self._connected = False
        self.encrypted = False
        self.authenticated = False
        self.proxy_authenticated = False
        self.auth_required = True
        self.proxy_auth_required = True
        # self.failed_on = ""

    async def disconnect(self):
        sockname = "Not connected"
        if self.writer:
            sockname = self.writer.get_extra_info("sockname")
        log.info(
            f"Disconnect called for socket: {sockname}. Total channels before: {self.channels}"
        )
        self.channels -= 1
        if self.channels:
            return

        self._disconnecting = True

        self.reset_state()

        log.info("No more channels... closing socket")
        await self._close_socket()

    async def _close_socket(self):
        """Lets other end know we're closed, then closes socket"""
        if self.writer and not self.writer.is_closing():
            log.info("Writing EOF on socket")
            try:
                self.writer.write_eof()
            except NotImplementedError:
                log.warn("Can't write EOF on SSL socket")

            self.writer.close()
            await self.writer.wait_closed()
        self.reader = None
        self.writer = None
        self._disconnecting = False
        self.reset_state()
