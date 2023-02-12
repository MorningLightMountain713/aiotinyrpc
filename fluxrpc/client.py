#!/usr/bin/env python
# -*- coding: utf-8 -*-

import secrets
import sys
from collections import namedtuple
from typing import Any, Callable, Dict, List

from .exc import RPCError
from .protocols import RPCBatchResponse, RPCProtocol, RPCRequest
from .transports import ClientTransport

RPCCall = namedtuple("RPCCall", "method args kwargs")
"""Defines the elements of an RPC call.

RPCCall is used with :py:meth:`~tinyrpc.client.RPCClient.call_all`
to provide the list of requests to be processed. Each request contains the
elements defined in this tuple.
"""

RPCCallTo = namedtuple("RPCCallTo", "transport method args kwargs")
"""Defines the elements of a RPC call directed to multiple transports.

RPCCallTo is used with :py:meth:`~tinyrpc.client.RPCClient.call_all`
to provide the list of requests to be processed.
"""


class RPCClient(object):
    """Client for making RPC calls to connected servers.

    :param protocol: An :py:class:`~tinyrpc.RPCProtocol` instance.
    :type protocol: RPCProtocol
    :param transport: The data transport mechanism
    :type transport: ClientTransport
    """

    def __init__(
        self, protocol: RPCProtocol, transport: ClientTransport, id: str = ""
    ) -> None:
        self.protocol = protocol
        self.transport = transport
        self.id = id if id else secrets.token_urlsafe(12)

    @property
    def is_proxied(self):
        return bool(self.transport.proxy_target)

    @property
    def proxy_host_port(self) -> tuple:
        return self.transport.proxy_source

    @property
    def connected(self):
        return self.transport.connected


    async def _send_and_handle_reply(self, req: RPCRequest, one_way: bool = False):
        if self.transport.is_async:
            reply = await self.transport.send_message(req.serialize(), not one_way)

        else:
            # sends and expects for reply if connection is not one way
            reply = self.transport.send_message(req.serialize(), not one_way)

        if one_way:
            return

        # waits for reply
        response = self.protocol.parse_reply(reply)

        if hasattr(response, "error"):
            raise RPCError("Error calling remote procedure: %s" % response.error)

        return response

    async def call(
        self,
        method: str,
        args: List = [],
        kwargs: Dict = {},
        one_way: bool = False,
    ) -> Any:
        """Calls the requested method and returns the result.

        If an error occured, an :py:class:`~tinyrpc.exc.RPCError` instance
        is raised.

        :param method: Name of the method to call.
        :param args: Arguments to pass to the method.
        :param kwargs: Keyword arguments to pass to the method.
        :param one_way: Whether or not a reply is desired.
        """
        req = self.protocol.create_request(method, args, kwargs, one_way)

        rep = await self._send_and_handle_reply(req, one_way)

        if one_way:
            return

        return rep.result

    def call_all(self, requests: List[RPCCall]) -> List[Any]:
        """Calls the methods in the request in parallel.

        When the :py:mod:`gevent` module is already loaded it is assumed to be
        correctly initialized, including monkey patching if necessary.
        In that case the RPC calls defined by ``requests`` are performed in
        parallel otherwise the methods are called sequentially.

        :param requests: A list of either :py:class:`~tinyrpc.client.RPCCall` or :py:class:`~tinyrpc.client.RPCCallTo`
                         elements.
                         When RPCCallTo is used each element defines a transport.
                         Otherwise the default transport set when RPCClient is
                         created is used.
        :return: A list with replies matching the order of the requests.
        """
        threads = []

        if "gevent" in sys.modules:
            # assume that gevent is available and functional, make calls in parallel
            import gevent

            for r in requests:
                req = self.protocol.create_request(r.method, r.args, r.kwargs)
                tr = r.transport.transport if len(r) == 4 else None
                threads.append(
                    gevent.spawn(self._send_and_handle_reply, req, False, tr, True)
                )
            gevent.joinall(threads)
            return [t.value for t in threads]
        else:
            # call serially
            for r in requests:
                req = self.protocol.create_request(r.method, r.args, r.kwargs)
                tr = r.transport.transport if len(r) == 4 else None
                threads.append(self._send_and_handle_reply(req, False, tr, True))
            return threads

    def get_proxy(
        self, prefix: str = "", plugins: list = []
    ) -> "RPCProxy":
        """Convenience method for creating a proxy.

        :param prefix: Passed on to :py:class:`~tinyrpc.client.RPCProxy`.
        :param one_way: Passed on to :py:class:`~tinyrpc.client.RPCProxy`.
        :return: :py:class:`~tinyrpc.client.RPCProxy` instance.
        """
        # plugins = await self.call("list_plugins", one_way=False)

        return RPCProxy(self, prefix, plugins)

    def batch_call(self, calls: List[RPCCallTo]) -> RPCBatchResponse:
        """Experimental, use at your own peril."""
        req = self.protocol.create_batch_request()

        for call_args in calls:
            req.append(self.protocol.create_request(*call_args))

        return self._send_and_handle_reply(req)


class RPCProxy(object):
    """Create a new remote proxy object.

    Proxies allow calling of methods through a simpler interface. See the
    documentation for an example.

    :param client: An :py:class:`~tinyrpc.client.RPCClient` instance.
    :param prefix: Prefix to prepend to every method name.
    :param one_way: Passed to every call of
                    :py:func:`~tinyrpc.client.call`.
    """

    def __init__(
        self,
        client: RPCClient,
        prefix: str = "",
        plugins: list = [],
    ) -> None:
        self.client = client
        self.prefix = prefix
        self.one_way = False
        self.plugins = plugins

        for plugin in plugins:
            setattr(
                self,
                plugin,
                RPCProxy(
                    self.client,
                    prefix=plugin,
                ),
            )

    def notify(self):
        """Sets the next rpc call as a notification"""
        self.one_way = True

    def get_transport(self):
        return self.client.transport

    def __getattr__(self, name: str) -> Callable:
        """Returns a proxy function that, when called, will call a function
        name ``name`` on the client associated with the proxy.
        """
        # this is necessary. Even copy.copy doesn't work. For some reason this is pass by reference if using self.one_way
        tmp_one_way = self.one_way
        proxy_func = lambda *args, **kwargs: self.client.call(
            self.prefix + name,
            args,
            kwargs,
            one_way=tmp_one_way,
        )
        # above was pass by value
        self.one_way = False

        return proxy_func
