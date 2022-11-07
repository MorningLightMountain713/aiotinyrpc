#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zmq

from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.transports.zmq import ZmqClientTransport
from aiotinyrpc import RPCClient

ctx = zmq.Context()

rpc_client = RPCClient(
    JSONRPCProtocol(),
    ZmqClientTransport.create(ctx, 'tcp://127.0.0.1:5001')
)

remote_server = rpc_client.get_proxy()

# call a method called 'reverse_string' with a single string argument
result = remote_server.reverse_string('Hello, World!')

print "Server answered:", result
