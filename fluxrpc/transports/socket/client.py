from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path
from typing import Callable, Optional
import inspect
from dataclasses import dataclass, field
from contextlib import asynccontextmanager
from collections import deque

import aiofiles
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from fluxrpc.auth import SignatureAuthProvider
from fluxrpc.transports import ClientTransport
from fluxrpc.transports.socket.messages import (
    AesKeyMessage,
    ChallengeReplyMessage,
    EncryptedMessage,
    FileEntryStreamMessage,
    Message,
    ProxyMessage,
    ProxyResponseMessage,
    PtyClosedMessage,
    PtyMessage,
    PtyResizeMessage,
    RpcReplyMessage,
    RpcRequestMessage,
    RsaPublicKeyMessage,
    SerializedMessage,
    SessionKeyMessage,
    TestMessage,
    LivelinessMessage,
    AesRekeyMessage,
)

import ssl
import tempfile

from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

from fluxrpc.auth import AuthProvider, AuthReplyMessage, ChallengeMessage
from fluxrpc.log import log

from .symbols import (
    AUTH_ADDRESS_REQUIRED,
    AUTH_DENIED,
    NO_SOCKET,
    PROXY_AUTH_ADDRESS_REQUIRED,
    PROXY_AUTH_DENIED,
    PROXY_NO_SOCKET,
    AUTH_TIMEOUT,
    CHALLENGE_TIMEOUT,
    ENCRYPTION_TIMEOUT,
    FORWARDING_TIMEOUT,
)


def bytes_to_human(num, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


@dataclass
class Channel:
    """A dedicated message queue to segregate messages per flow on the socket"""

    id: int
    exclusive: bool = False
    in_use: bool = False
    q: asyncio.Queue = field(default_factory=asyncio.Queue)

    async def send_message(self):
        ...


class ChannelError(Exception):
    ...


@dataclass
class ChannelManager:
    """Handles the day to day life of a channel"""

    channels: list[Channel] = field(default_factory=list)
    channel_count: int = 0
    cm: Channel | None = None

    def __bool__(self):
        return bool(self.channels)

    def __repr__(self) -> str:
        return str(self.count)

    # def __aenter__(self):
    #     self.cm = self.get_channel()
    #     return self.cm

    # async def __aexit__(self, exc_type, exc_value, traceback):
    #     self.cm.in_use = False
    #     self.cm = None

    @property
    def count(self):
        """Returns count of used / non used channels"""
        return len(self.channels)

    def get_channel(
        self, chan_id: int | None = None, exclusive: bool = False
    ) -> Channel | None:
        if chan_id:
            chan = self.get_channel_by_id(chan_id)

        elif exclusive:
            chan: Channel = next(
                filter(lambda x: not x.in_use and x.exclusive, self.channels), None
            )

        else:
            chan: Channel = next(
                filter(lambda x: not x.in_use and not x.exclusive, self.channels), None
            )

        if not chan:
            return

        while not chan.q.empty():
            msg = chan.q.get_nowait()
            print("REMOVING STALE MESSAGE", msg)

        chan.in_use = True

        return chan

    # def refresh_channel_id(self, id):
    #     """Channel timed out, dump id and add a new one"""
    #     chan = self.get_channel_by_id(id)

    #     if not chan:
    #         return

    #     chan.id = self.get_next_free_id()

    async def release_channel(self, id):
        for chan in self.channels:
            if id == chan.id:
                chan.in_use = False

    def get_channel_by_id(self, id) -> Channel | None:
        return next(filter(lambda x: x.id == id, self.channels), None)

    def get_next_free_id(self) -> int:
        free_id = self.channel_count
        self.channel_count += 1

        return free_id

    def add_channel(self, exclusive: bool = False):
        id = self.get_next_free_id()
        # id = len(self.channels)
        self.channels.append(Channel(id, exclusive))

    def remove_all_channels(self):
        self.channels = []

    def remove_channel(self, chan_id: int | None):
        """Remove the first non used channel or an exclusive channel if chan_id used"""
        if chan_id:
            chan = self.get_channel_by_id(chan_id)
            if chan:
                self.channels.remove(chan)
            return

        for channel in self.channels.copy():
            if not channel.in_use and not channel.exclusive:
                self.channels.remove(channel)
                break


@dataclass
class Session:
    """A lazy loaded connection to a FluxVault Agent

    A transport can only have one session, but many channels

    Starting a session shows the intent of running tasks on an agent, it doesn't
    start the connection. It's not until a task is actually run that the connection
    is initiated.

    Once it's initiated, it stays open until the session is ended.

    This means that while a session is open, (a grouping of tasks running, maybe via
    a few different function calls) you can still connect outside of the session and create
    a channel. A channel is just a multiplexing of `connections` onto a single socket. Means
    we only have to ever manage one set of encryption keys per Agent <-> Keeper relationship
    """

    transport: EncryptedSocketClientTransport
    connected: bool = False
    connection_attempted: bool = False
    started: bool = False
    signing_address: str = ""

    async def __aenter__(self):
        self.start()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        self.end()

    async def start(self, connect=False):
        if not self.started:
            log.info(
                f"Session started for {self.transport.address}:{self.transport.port}"
            )
        # log.info(f"Transport id: {id(self.transport)}")
        self.started = True

        if connect:
            await self.connect()

    async def connect(self, signing_key: str = ""):
        self.connection_attempted = True

        if signing_key:
            auth_provider = SignatureAuthProvider(key=signing_key)
            self.transport.auth_provider = auth_provider

        await self.transport.connect()

        if not self.transport.connected and signing_key:
            log.error("Cannot connect after retrying with authentication...")
            return

        if self.transport.connected:
            self.connected = True
            return

        log.info("Transport not connected... checking connection requirements...")
        log.info(f"Failed on {self.transport.failed_on}")

        if self.transport.failed_on == NO_SOCKET:
            return

        address_type = ""
        # match/case
        if self.transport.failed_on in [AUTH_ADDRESS_REQUIRED, AUTH_DENIED]:
            address_type = "auth_address"
        elif self.transport.failed_on in [
            PROXY_AUTH_ADDRESS_REQUIRED,
            PROXY_AUTH_DENIED,
        ]:
            address_type = "proxy_auth_address"

        if address_type:
            self.signing_address = getattr(self.transport, address_type)

    def reset(self):
        self.connected = False
        self.connection_attempted = False
        self.started = False
        self.signing_address = ""

    async def end(self):
        if self.connected:
            await self.transport.disconnect()
        self.reset()


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
        rekey_timer: int = 1800,
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
        self.aes_keys: deque = deque([], maxlen=2)
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
        # change these to futures
        self.on_pty_data_callback = on_pty_data_callback
        self.on_pty_closed_callback = on_pty_closed_callback
        # group these
        self.encrypted_event = asyncio.Event()
        self.forwarding_event = asyncio.Event()
        self.authentication_event = asyncio.Event()
        self.challenge_complete_event = asyncio.Event()
        self.rekey_timer = rekey_timer

        self.rekey_manager: asyncio.Task | None = None
        # rename this to channels
        self.channels = ChannelManager()

        # self.channels = 0
        self.read_socket_task: asyncio.Task | None = None
        self._proxy_source = ()
        self.progress = Progress(
            TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
            # transient=True,
        )
        self.session = Session(self)
        self.sockname = "Not connected"
        self.peername = "Not connected"

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
    def port(self) -> str:
        return self._port

    @property
    def proxy_source(self) -> tuple:
        return self._proxy_source

    @classmethod
    def clone(
        cls, transport: EncryptedSocketClientTransport
    ) -> EncryptedSocketClientTransport:
        address = transport.address
        port = transport._port
        auth_provider = transport.auth_provider
        proxy_target = transport.proxy_target
        on_pty_data_callback = transport.on_pty_data_callback
        on_pty_closed_callback = transport.on_pty_closed_callback

        return cls(
            address,
            port,
            auth_provider,
            proxy_target,
            on_pty_data_callback,
            on_pty_closed_callback,
        )

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

    async def writeable(self) -> bool:
        """Writes on the socket and checks it's all good"""
        if not self.writer:
            return False

        try:
            res = await asyncio.wait_for(
                self.send_message(LivelinessMessage()), timeout=3
            )
        except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError):
            return False

        if not isinstance(res, LivelinessMessage):
            return False

        return True if res.text == "ohcE" else False

    def get_exclusive_channel(self) -> int | None:
        chan: Channel = self.channels.get_channel(exclusive=True)
        if not chan:
            raise ChannelError(
                "No exclusive channels, did you request it when connecting?"
            )

        return chan.id

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

    async def forwarding_message_handler(self, msg: ProxyResponseMessage):
        if not msg.success and self.proxy_target:
            self.failed_on = PROXY_NO_SOCKET

        if msg.success and self.proxy_target:
            # from this point we are being proxied
            self._proxy_source = msg.socket_details
            if self.proxy_ssl:
                await self.upgrade_socket()

            # these all need timeouts
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

    def set_rekey(self, value: bool):
        # print(f"Setting rekey: {value}")
        self.rekeying = value

    def decrypt(self, msg: EncryptedMessage) -> Message:
        try:
            decrypted = msg.decrypt(self.aes_keys[-1])
        except ValueError as e:  # wrong key or no keys
            if self.rekeying:
                decrypted = msg.decrypt(self.aes_keys[0])
            else:
                raise e from None
        except Exception as e:
            print("blah123")
            print(repr(e))
            exit(0)

        return decrypted

    async def encryption_message_handler(self, msg):
        # this is always received before encrypted message
        # print(f"Encrypted msg handler: {type(msg)}")
        if isinstance(msg, RsaPublicKeyMessage):
            rsa_public_key = msg.key.decode("utf-8")

            new_aes_key = get_random_bytes(16).hex().encode("utf-8")

            try:
                # this is a rekey event
                if self.encrypted:
                    self.rekeying = True
                    self.loop.call_later(1, self.set_rekey, False)

                self.aes_keys.append(new_aes_key)
            except Exception as e:
                print(repr(e))
                exit(0)

            try:
                session_key_message = self.session_key_message(
                    rsa_public_key, new_aes_key
                )
            except ValueError:
                # ToDo: move this to received message
                log.error("Malformed (or no) RSA key received... skipping")
                self.writer.close()
                await self.writer.wait_closed()
                self._connected = False
                return
            except Exception as e:
                print(repr(e))
                exit(0)

            if self.encrypted:
                session_key_message = session_key_message.encrypt(self.aes_keys[0])

            try:
                await self.send(session_key_message.serialize())
            except Exception as e:
                print(e)
                print("blah")

        if isinstance(msg, EncryptedMessage):
            decrypted_test_message = self.decrypt(msg)

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
            # use the newest key for encryption
            try:
                msg = msg.encrypt(self.aes_keys[-1])
            except Exception as e:
                print(repr(e))
                exit(0)
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

    async def ensure_connected(self):
        if not await self.writeable():
            await self.connect()

        while not await self.writeable():
            log.warning(
                f"Reconnection to {self.address}:{self.port} failed, sleeping 30s"
            )
            await asyncio.sleep(30)
            log.info(f"Reconnecting to {self.address}:{self.port}")
            await self.connect()
            # if not self.failed_on:
            #     break

        log.info(f"Socket to {self.address}:{self.port} is writeable")

    @asynccontextmanager
    async def connection_manager(self):
        con = await self.connect()

        if not self.connected:
            raise ConnectionError()

        try:
            yield con
        finally:
            await self.disconnect()

    async def send_rekey_every(self, commanded_delay: int):
        """Will send a rekey message to the agent every <delay> seconds"""
        delay = commanded_delay
        while True:
            await asyncio.sleep(delay)
            delay = commanded_delay

            start = time.monotonic()
            msg = AesRekeyMessage(get_random_bytes(4))
            msg = msg.encrypt(self.aes_keys[-1])

            await self.send(msg.serialize())

            delay = delay - (time.monotonic() - start)
            log.info(f"Rekeying, then sleeping {delay}s")

    async def connect(self, exclusive: bool = False):
        # log.info(f"DEBUG: all tasks count: {len(asyncio.all_tasks())}")
        channel = None

        # start fresh - not 100% on this
        self.failed_on = ""

        # log.info(f"Transport id: {id(self)} Connecting...")
        # if self._connecting:
        #     log.info("Connecting... adding channel")
        #     # isn't this wrong???
        #     channel = self.channels.add_channel(exclusive)

        while self._connecting or self._disconnecting:
            await asyncio.sleep(0.02)

        if self.failed_on == NO_SOCKET:
            # we were waiting on the joker before us, and he just finished and failed on no socket, no point
            # retrying immediately
            # do we need to remove channel?
            return

        if self.channels:
            # self.channels += 1
            channel = self.channels.add_channel(exclusive)

            # log.info(f"Adding new channel. Total: {self.channels}")
            return channel

        self._connecting = True

        await self._connect()

        if not self.reader and not self.writer:
            self._connecting = False
            self.failed_on = NO_SOCKET
            log.error("No reader or writer... Error connecting")
            return

        # self.channels += 1
        channel = self.channels.add_channel(exclusive)

        self.read_socket_task = asyncio.create_task(self.read_socket_loop())

        try:
            await asyncio.wait_for(self.challenge_complete_event.wait(), timeout=10)
        except asyncio.TimeoutError:
            await self.disconnect()
            self.failed_on = CHALLENGE_TIMEOUT
            self._connecting = False
            log.error("Timed out waiting for challenge event, probably broken socket")
            return

        self.challenge_complete_event.clear()

        if self.auth_required and not self.auth_provider:
            self.auth_error = "Auth required and no auth provider set"
            log.warning(self.auth_error)
            self.failed_on = AUTH_ADDRESS_REQUIRED
            await self.disconnect()
            self._connecting = False
            return

        if self.auth_required:
            try:
                await asyncio.wait_for(self.authentication_event.wait(), timeout=10)
            except asyncio.TimeoutError:
                await self.disconnect()
                self.failed_on = AUTH_TIMEOUT
                self._connecting = False
                log.error(
                    "Timed out waiting for authentication event, probably broken socket"
                )
                return

            self.authentication_event.clear()

            if not self.authenticated:
                log.error("Authentication error")
                self.failed_on = AUTH_DENIED
                await self.disconnect()
                self._connecting = False
                return

            log.info("Connection authenticated!")

        await self.send_forwarding_message()

        try:
            await asyncio.wait_for(self.forwarding_event.wait(), timeout=10)
        except asyncio.TimeoutError:
            self.failed_on = FORWARDING_TIMEOUT
            await self.disconnect()
            self._connecting = False
            log.error("Timed out waiting for forwarding event, probably broken socket")
            return

        self.forwarding_event.clear()

        # this happens if proxy connection fails
        if self.failed_on:
            log.error(f"Failed to connect. Failed on: {self.failed_on}")
            await self.disconnect()
            self._connecting = False

            return

        try:
            await asyncio.wait_for(self.encrypted_event.wait(), timeout=10)
        except asyncio.TimeoutError:
            self.failed_on = ENCRYPTION_TIMEOUT
            await self.disconnect()
            self._connecting = False
            log.error("Timed out waiting for encrypted event, probably broken socket")
            return

        self.encrypted_event.clear()

        # self.channels += 1
        log.debug(f"Connection encrypted Total channels: {self.channels}")
        self._connected = True
        self._connecting = False

        self.rekey_manager = asyncio.create_task(
            self.send_rekey_every(self.rekey_timer)
        )

        return channel

    async def _connect(self):
        """Connects to socket server. Tries a max of 3 times"""
        log.info(f"Opening connection to {self._address} on port {self._port}")
        retries = 3

        for n in range(retries):
            con = asyncio.open_connection(self._address, self._port)
            try:
                self.reader, self.writer = await asyncio.wait_for(con, timeout=3)
            except asyncio.TimeoutError:
                log.warning(f"Timeout error connecting to {self._address}")
            except ConnectionError:
                log.warning(f"Connection error connecting to {self._address}")
            except OSError:
                log.warning(f"Network error connection to {self._address}")
            else:
                self.sockname = self.writer.get_extra_info("sockname")
                self.peername = self.writer.get_extra_info("peername")
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
        timeout = 60
        # peername = self.writer.get_extra_info("peername")
        while self.reader and not self.reader.at_eof():
            # start = time.monotonic()
            try:
                coro = self.reader.readuntil(self.separator)
                data = await asyncio.wait_for(coro, timeout=timeout)

            except asyncio.TimeoutError as e:
                log.error(f"Timeout of {timeout}s exceeded for socket read, returning")
                self._connected = False
                self.encrypted = False
                # self.channels.remove_all_channels()
                break
            except asyncio.IncompleteReadError as e:
                # log.debug("EOF reached, socket closed")
                self._connected = False
                self.encrypted = False
                # self.channels.remove_all_channels()
                break
            except ConnectionResetError as e:
                self._connected = False
                self.encrypted = False
                # self.channels.remove_all_channels()
                break
            except ssl.SSLError as e:
                log.error(e)
                self._connected = False
                self.encrypted = False
                # self.channels.remove_all_channels()
                break
            except asyncio.LimitOverrunError as e:
                data = []

                while True:
                    current = await self.reader.read(64000)
                    if current.endswith(self.separator):
                        data.append(current)
                        break

                    data.append(current)

                count = re.findall(b"\\<\\?!!\\?\\>", data[-1])

                # split messages
                if len(count) > 1:
                    multi_message_bytes = data.pop()
                    extra_messages = multi_message_bytes.split(b"<?!!?>")
                    # or just remove the last item?
                    extra_messages = list(filter(None, extra_messages))
                    last_data = extra_messages.pop(0)
                    data.append(last_data + b"<?!!?>")

                data = b"".join(data)

            except Exception as e:
                print("in read socket loop")
                print(repr(e))
                self._connected = False
                self.encrypted = False
                # self.channels.remove_all_channels()
                break

            message = data.rstrip(self.separator)

            all_messages = [message, *extra_messages]
            extra_messages = []

            for message in all_messages:
                try:
                    message = SerializedMessage(message).deserialize()
                except Exception as e:
                    print("can't deserialize in for")
                    print(repr(e))
                    continue

                log.debug(f"Received : {type(message).__name__}")

                if self.encrypted:
                    message = self.decrypt(message)
                    log.debug(f"Decrypted Received : {type(message).__name__}")

                match message:
                    case PtyMessage():
                        # our_socket = self.writer.get_extra_info("sockname")
                        await self.on_pty_data_callback(self.sockname, message.data)

                    case RpcReplyMessage():
                        chan = self.channels.get_channel_by_id(message.chan_id)

                        if chan:
                            chan.q.put_nowait(message)

                        else:
                            log.warning(
                                f"Dropping message {message} with Unknown channel id: {message.chan_id}"
                            )

                    case ChallengeMessage() | AuthReplyMessage():
                        await self.authentication_message_handler(message)

                    case ProxyResponseMessage():
                        asyncio.create_task(self.forwarding_message_handler(message))

                    case RsaPublicKeyMessage() | TestMessage():
                        await self.encryption_message_handler(message)

                    # This is our test message as we're not encrypted yet
                    # it could be part of the handler above but more clear here
                    case EncryptedMessage():
                        await self.encryption_message_handler(message)

                    case PtyClosedMessage():
                        # our_socket = self.writer.get_extra_info("sockname")
                        await self.on_pty_closed_callback(self.sockname)

                    case _:
                        log.error(f"Unknown message: {message}")

                # log.info(f"Time to loop for {peername}: {time.monotonic() - start}")

        log.debug("Finished read socket loop")

    async def send_pty_message(self, data):
        msg = PtyMessage(data)
        if self.encrypted:
            msg = msg.encrypt(self.aes_keys[-1])

        self.writer.write(msg.serialize() + self.separator)
        await self.writer.drain()

    async def stream_files(self, files: list[tuple[Path, str]]):
        # create a channel if socket already connected
        await self.connect()
        for local_path, remote_path in files:
            eof = False

            log.info(f"Client transport: About to stream file {local_path.name}")

            size = local_path.stat().st_size

            with self.progress:
                task_id = self.progress.add_task(
                    "download", filename=local_path.name, start=False
                )
                self.progress.update(task_id, total=size)

                async with aiofiles.open(local_path, "rb") as f:
                    self.progress.start_task(task_id)
                    start = time.time()
                    while True:
                        if eof:
                            break

                        # 50Mb
                        data = await f.read(1048576 * 50)
                        self.progress.update(task_id, advance=len(data))

                        if not data:
                            end = time.time()
                            log.info(
                                f"Client Transport: Transdfer complete. Elapsed: {end - start}"
                            )
                            eof = True

                        msg = FileEntryStreamMessage(data, remote_path, eof)

                        if self.encrypted:
                            msg = msg.encrypt(self.aes_keys[-1])

                        self.writer.write(msg.serialize() + self.separator)
                        await self.writer.drain()
            self.progress.remove_task(task_id)
        await self.disconnect()
        #         # await asyncio.sleep(0.01)

    async def send_pty_resize_message(self, rows, cols):
        msg = PtyResizeMessage(rows, cols)
        if self.encrypted:
            msg = msg.encrypt(self.aes_keys[-1])

        self.writer.write(msg.serialize() + self.separator)
        await self.writer.drain()

    async def send(self, data: bytes):
        self.writer.write(data + self.separator)
        await self.writer.drain()

    async def send_message(
        self,
        message: Message | bytes,
        expect_reply: bool = True,
        timeout: int = 45,
        channel: int | None = None,
    ) -> Message | None:
        """Writes data on the socket, this is the main entrypoint"""

        chan = self.channels.get_channel(chan_id=channel)
        # since we are reusing channels, there is a small chance there could be
        # a stale message in there. Just dump them. Ideally, would just use unique
        # channel id's - however this adds overhead as we have to send these over the socket
        # If it becomes a problem, will move sequencial channel ids
        if not chan:
            log.warning(f"No free channels... probably timed out... returning")
            return

        # from upper RPC layer
        if isinstance(message, bytes):
            # should always be encrypted here?

            # print(f"Received channel: {chan.id}")
            message = RpcRequestMessage(chan.id, message)
            # print("Payload size", bytes_to_human(len(message.payload)))
        if self.encrypted:
            log.debug(f"Sending encrypted message: {message}")
            message = message.encrypt(self.aes_keys[-1])
        else:
            log.debug(f"Sending message in the clear: {message}")

        # catch
        await self.send(message.serialize())

        if not expect_reply:
            self.channels.release_channel(chan.id)
        else:
            # upper layer catches this
            res = await asyncio.wait_for(chan.q.get(), timeout=timeout)

            if isinstance(res, RpcReplyMessage):
                res = res.payload
            elif isinstance(res, LivelinessMessage):
                ...
            else:
                log.error(f"Waiting for RPC message but received something else: {res}")

            # log.info(f"Releasing channel id: {chan.id}")
            await self.channels.release_channel(chan.id)
            return res

    def reset_state(self):
        self._connected = False
        self.encrypted = False
        self.authenticated = False
        self.proxy_authenticated = False
        self.auth_required = True
        self.proxy_auth_required = True
        self.sockname = "Not connected"
        self.peername = "Not connected"

        if self.read_socket_task:
            self.read_socket_task.cancel()

    async def disconnect(self, chan_id: int | None = None):
        # this_frame = inspect.currentframe()
        # caller_frame = inspect.getouterframes(this_frame, 2)
        # print("caller name:", caller_frame[1][3])
        # print("caller", inspect.currentframe().f_back.f_code.co_name)

        log.info(
            f"Disconnect called for socket: {self.sockname} <-> {self.peername}. Total channels before: {self.channels}"
        )

        self.channels.remove_channel(chan_id)
        # self.channels -= 1
        # this shouldn't happen but yeah
        # self.channels = max(0, self.channels)

        if self.channels:
            return

        self._disconnecting = True

        # log.info("No more channels... closing socket")
        await self._close_socket()

    async def _close_socket(self):
        """Lets other end know we're closed, then closes socket"""
        if self.writer and not self.writer.is_closing():
            if self.rekey_manager:
                self.rekey_manager.cancel()
            # log.info("Writing EOF on socket")
            try:
                self.writer.write_eof()
            except NotImplementedError:
                pass
                # log.warn("Can't write EOF on SSL socket")
            except OSError:
                # socket is not connected
                pass

            self.writer.close()
            await self.writer.wait_closed()
        self.reader = None
        self.writer = None
        self._disconnecting = False
        self.reset_state()
