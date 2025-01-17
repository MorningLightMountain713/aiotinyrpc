#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zmq

from fluxrpc.dispatch import RPCDispatcher
from fluxrpc.protocols.jsonrpc import JSONRPCProtocol
from fluxrpc.server import RPCServer
from fluxrpc.transports.zmq import ZmqServerTransport

ctx = zmq.Context()
dispatcher = RPCDispatcher()
transport = ZmqServerTransport.create(ctx, "tcp://127.0.0.1:5001")

rpc_server = RPCServer(transport, JSONRPCProtocol(), dispatcher)


@dispatcher.public
def reverse_string(s):
    return s[::-1]


rpc_server.serve_forever()
