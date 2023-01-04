from __future__ import annotations  # 3.10 style

import asyncio
from typing import BinaryIO

import bson
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

from aiotinyrpc.log import log
from aiotinyrpc.transports import ServerTransport

from aiotinyrpc.transports.socket.messages import (
    RsaPublicKeyMessage,
    ChallengeMessage,
    SessionKeyMessage,
    SerializedMessage,
    TestMessage,
    ProxyMessage,
    ProxyResponseMessage,
    RpcRequestMessage,
    EncryptedMessage,
    RpcReplyMessage,
    PtyMessage,
    PtyResizeMessage,
    PtyClosedMessage,
)
from aiotinyrpc.auth import AuthProvider, ChallengeReplyMessage, AuthReplyMessage

import ssl

from dataclasses import dataclass, field

# pty stuff
import struct, fcntl, termios, select, os, signal


@dataclass
class KeyData:
    rsa_key: str = ""
    aes_key: str = ""
    private: str = ""
    public: str = ""

    def generate(self):
        self.rsa_key = RSA.generate(2048)
        self.private = self.rsa_key.export_key()
        self.public = self.rsa_key.publickey().export_key()


@dataclass
class EncryptablePeerGroup:
    peers: list = field(default_factory=list)

    def __len__(self):
        return len(self.peers)

    def __iter__(self):
        yield from self.peers

    async def destroy_peer(self, id):
        log.info(f"Destroying peer: {id}")
        peer = self.get_peer(id)
        if peer:
            peer.writer.close()
            await peer.writer.wait_closed()
            self.peers = [x for x in self.peers if x.id != id]

    async def destroy_peer_timer(self, id, timeout):
        await asyncio.sleep(timeout)
        log.debug(f"Destroying peer{id}, timed out")
        await self.destroy_peer(id)

    def get_peer(self, id):
        for peer in self.peers:
            if peer.id == id:
                return peer

    def add_peer(self, peer):
        self.peers.append(peer)

    async def destroy_all_peers(self):
        try:
            for peer in self.peers:
                await self.destroy_peer(peer.id)
        except Exception as e:
            print("destroy all peers exception")
            print(repr(e))

    async def start_peer_timeout(self, id):
        peer = self.get_peer(id)
        timeout = 10

        peer.timer = asyncio.create_task(self.destroy_peer_timer(peer.id, timeout))


@dataclass
class EncryptablePeer:
    id: tuple
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    key_data: KeyData = KeyData()
    encrypted: bool = False
    authenticated: bool = False
    separator = b"<?!!?>"
    # ToDo: multiple ptys
    pty: BinaryIO | None = None
    pid: int = 0
    random: str = ""
    proxied: bool = False
    timer: asyncio.Task | None = None
    challenge_complete_event: asyncio.Event = field(default_factory=asyncio.Event)
    forwarding_event: asyncio.Event = field(default_factory=asyncio.Event)

    async def send(self, msg: bytes):
        log.debug(f"Sending message: {bson.decode(msg)}")
        self.writer.write(msg + self.separator)
        await self.writer.drain()

    def handle_pty_message(self, message):
        host, msg = message

        if not self.pty:
            return

        if isinstance(msg, PtyResizeMessage):
            self.set_winsize(msg.rows, msg.cols)
        else:
            os.write(self.pty, msg.data)

    def set_winsize(self, row, col, xpix=0, ypix=0):
        log.debug("setting window size with termios")
        winsize = struct.pack("HHHH", row, col, xpix, ypix)
        fcntl.ioctl(self.pty, termios.TIOCSWINSZ, winsize)

    async def proxy_pty(self, separator: bytes):
        max_read_bytes = 1024 * 20

        while True:
            if not self.pty:
                log.warn("Remote end closed pty. Cleaning up...")
                break
            if self.pty:
                timeout_sec = 0
                data_ready, _, _ = select.select([self.pty], [], [], timeout_sec)
                if data_ready:
                    output = os.read(self.pty, max_read_bytes)
                    # this happens when subprocess closed
                    if output == b"":
                        log.warn(
                            "No output from read after select. Pty closed... cleaning up"
                        )
                        self.pty = None
                        self.pid = 0
                        break
                    # ToDo: should this be buffered?
                    msg = PtyMessage(output)
                    msg = msg.encrypt(self.key_data.aes_key)
                    self.writer.write(msg.serialize() + separator)
                    await self.writer.drain()
                    continue  # skip sleep if data (might be more data)
            await asyncio.sleep(0.01)

        log.info("Sending Pty closed message")
        msg = PtyClosedMessage(b"Process exited")
        msg = msg.encrypt(self.key_data.aes_key)
        self.writer.write(msg.serialize() + separator)
        try:
            await self.writer.drain()
        except Exception as e:  # Tighten
            log.error("error draining proxy pty in finally")
            log.error(repr(e))


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
        self.peers = EncryptablePeerGroup()
        self.rpc_messages = asyncio.Queue()
        self.control_messages = asyncio.Queue()
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

    async def begin_encryption(self, peer):
        peer.key_data.generate()
        msg = RsaPublicKeyMessage(peer.key_data.public)

        await peer.send(msg.serialize())
        await self.peers.start_peer_timeout(peer.id)

    async def send_challenge_message(self, peer: EncryptablePeer) -> bool:
        source = peer.writer.get_extra_info("sockname")

        msg = ChallengeMessage(source=source, auth_required=bool(self.auth_provider))

        if self.auth_provider:
            msg = self.auth_provider.generate_challenge(msg)

        await peer.send(msg.serialize())
        await self.peers.start_peer_timeout(peer.id)

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

    async def handle_auth_message(
        self, peer: EncryptablePeer, msg: ChallengeReplyMessage
    ):
        peer.timer.cancel()
        source = peer.writer.get_extra_info("sockname")

        if msg.close_connection:
            # client handler will do this
            # self.peers.destroy_peer(peer.id)
            log.info("Client requested close connecting... closing")
            peer.challenge_complete_event.set()
            return

        if not self.auth_provider:
            log.info("No auth required by ourselves, continue")
            peer.challenge_complete_event.set()
            return

        peer.authenticated = self.auth_provider.verify_auth(msg)
        resp = AuthReplyMessage(source=source, authenticated=peer.authenticated)

        await peer.send(resp.serialize())

        log.info(f"Auth provider authenticated: {peer.authenticated}")
        peer.challenge_complete_event.set()

    async def handle_forwarding_message(self, peer, msg):
        resp = ProxyResponseMessage(False)
        if msg.proxy_required:
            success, proxy_id = await self.setup_forwarding(
                msg.proxy_target, msg.proxy_port, peer
            )
            resp.success = success
            resp.socket_details = proxy_id
            log.debug("Response message")
            log.debug(resp)
            await peer.send(resp.serialize())
            peer.forwarding_event.set()

            if not success:
                log.error("Not proxied... closing socket")
                await self.peers.destroy_peer(peer.id)
            return

        await peer.send(resp.serialize())
        peer.forwarding_event.set()

    async def handle_encryption_message(self, peer, msg):
        peer.timer.cancel()

        if isinstance(msg, SessionKeyMessage):
            aes_key = self.parse_session_key_message(peer.key_data.private, msg)

            peer.key_data.aes_key = aes_key

            # Send a test encryption request, always include random data
            peer.random = get_random_bytes(16).hex()
            test_msg = TestMessage(peer.random)
            encrypted_test_msg = test_msg.encrypt(aes_key)

            await peer.send(encrypted_test_msg.serialize())

        if isinstance(msg, EncryptedMessage):
            response = msg.decrypt(peer.key_data.aes_key)

            if (
                response.text == "TestEncryptionMessageResponse"
                and response.fill == peer.random[::-1]
            ):
                peer.encrypted = True
            log.info(f"Socket is encrypted: {peer.encrypted}")

    async def setup_forwarding(self, host, port, peer) -> tuple:
        """Connects to socket server. Tries a max of 3 times"""
        log.info(f"Proxying connection from {peer.id} to {host} on port {port}")
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
            peer.proxied = True
            pipe1 = self.pipe(peer.reader, proxy_writer)
            pipe2 = self.pipe(
                proxy_reader, peer.writer, self.peers.destroy_peer, peer.id
            )

            asyncio.create_task(pipe1)
            asyncio.create_task(pipe2)

            return (True, proxy_writer.get_extra_info("sockname"))
        return (False, None)

    async def proxy_pty(self, peer):
        log.info("Received proxy pty request... forwarding local pty to remote socket")
        task = self.sockets[peer].proxy_pty(self.separator)
        asyncio.create_task(task)

    def attach_pty(self, pid, pty, peer):
        log.info(f"Attaching to pty for peer: {peer}")
        try:
            self.sockets[peer].pty = pty
            self.sockets[peer].pid = pid
        except Exception as e:
            print(repr(e))

    def detach_pty(self, peer):
        log.info("detaching pty")
        self.sockets[peer].pty = None
        if self.sockets[peer].pid:
            os.kill(self.sockets[peer].pid, signal.SIGKILL)

    async def pipe(self, reader, writer, callback=None, id=""):
        try:
            while not reader.at_eof():
                writer.write(await reader.read(2048))
        finally:
            log.debug(f"Closing pipe for proxied connection")
            if callback:
                await callback(id)
            else:
                writer.close()
                await writer.wait_closed()

    async def handle_client(self, reader, writer):
        client_id = writer.get_extra_info("peername")
        log.info(f"Peer connected: {client_id}")

        peer = EncryptablePeer(client_id, reader, writer)
        self.peers.add_peer(peer)

        if self.verify_source_address and not await self.valid_source_ip(id[0]):
            log.warn("Source IP address not verified... dropping")
            await self.peers.destroy_peer(peer.id)
            return

        asyncio.create_task(self.read_socket_loop(peer))

        await self.send_challenge_message(peer)

        await peer.challenge_complete_event.wait()
        peer.challenge_complete_event.clear()

        if not peer.authenticated and self.auth_provider:
            log.error("Peer not authenticated... destroying socket")
            await self.peers.destroy_peer(peer.id)
            return

        # ToDo: do this better. start from this end
        await peer.forwarding_event.wait()
        peer.forwarding_event.clear()

        if not peer.proxied:
            await self.begin_encryption(peer)
        log.info("Handle client finished... waiting on read loop")

    async def read_socket_loop(self, peer):
        while peer.reader and not peer.proxied and not peer.reader.at_eof():
            try:
                data = await peer.reader.readuntil(separator=self.separator)
            except asyncio.exceptions.IncompleteReadError:
                log.info(f"Reader is at EOF. Peer: {peer.id}")
                break
            except asyncio.LimitOverrunError as e:
                data = []
                while True:
                    current = await peer.reader.read(64000)
                    if current.endswith(self.separator):
                        data.append(current)
                        break
                    data.append(current)
                data = b"".join(data)
            except BrokenPipeError:
                # ToDo: fix this?
                log.error(f"Broken pipe")
                break

            message = data.rstrip(self.separator)

            try:
                message = SerializedMessage(message).deserialize()
            except Exception as e:
                # ToDo: fix this
                log.error(repr(e))
                continue

            log.debug(f"Received : {type(message).__name__}")

            if peer.encrypted:
                message = message.decrypt(peer.key_data.aes_key)

            if isinstance(message, (PtyMessage, PtyResizeMessage)):
                peer.handle_pty_message(message)
                continue

            if isinstance(message, ChallengeReplyMessage):
                await self.handle_auth_message(peer, message)
                continue

            # Encrypted message is the test message (peer isn't encrypted)
            if isinstance(message, (SessionKeyMessage, EncryptedMessage)):
                await self.handle_encryption_message(peer, message)
                continue

            if isinstance(message, ProxyMessage):
                await self.handle_forwarding_message(peer, message)
                continue

            if isinstance(message, RpcRequestMessage):
                log.debug(
                    f"Message received (decrypted and decoded): {bson.decode(message.payload)})"
                )
                await self.rpc_messages.put((peer.id, message.payload))

            else:
                log.error(f"Unknown message: {message}")

        log.debug(f"Read socket loop finished. peer.proxied: {peer.proxied}")
        if not peer.proxied:
            # reader at eof
            await self.peers.destroy_peer(peer.id)

    async def stop_server(self):
        log.info("Stopping server")
        await self.peers.destroy_all_peers()
        log.info("after destroy peers")
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

    async def receive_message(self) -> tuple:
        addr, message = await self.rpc_messages.get()
        # message = message.as_dict()
        return addr, message

    async def send_reply(self, context: tuple, data: bytes):
        msg = RpcReplyMessage(data)
        peer = self.peers.get_peer(context)

        log.debug(
            f"Decoded RPC response (before encryption): {bson.decode(msg.payload)}"
        )
        # this should always be True
        if peer.encrypted:
            msg = msg.encrypt(peer.key_data.aes_key)

        await peer.send(msg.serialize())

    # try:
    #     task = asyncio.create_task(self.receive_on_socket(peer, reader))
    #     _, forwarding_msg = await asyncio.wait_for(task, timeout=10)

    # except (TypeError, asyncio.TimeoutError):
    #     log.warn("Malformed (or no) forwarding request... dropping")
    #     await self.disconnect_peer(writer, peer)
    #     return False
