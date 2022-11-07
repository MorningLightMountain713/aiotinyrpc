#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zmq

from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.transports.zmq import ZmqServerTransport
from aiotinyrpc.server import RPCServer
from aiotinyrpc.dispatch import RPCDispatcher

ctx = zmq.Context()
dispatcher = RPCDispatcher()
transport = ZmqServerTransport.create(ctx, "tcp://127.0.0.1:5001")

rpc_server = RPCServer(transport, JSONRPCProtocol(), dispatcher)


@dispatcher.public
def reverse_string(s):
    return s[::-1]


rpc_server.serve_forever()
