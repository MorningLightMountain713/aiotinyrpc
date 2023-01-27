#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zmq

from fluxrpc import RPCClient
from fluxrpc.protocols.jsonrpc import JSONRPCProtocol
from fluxrpc.transports.zmq import ZmqClientTransport

ctx = zmq.Context()

rpc_client = RPCClient(
    JSONRPCProtocol(),
    ZmqClientTransport.create(ctx, 'tcp://127.0.0.1:5001')
)

remote_server = rpc_client.get_proxy()

# call a method called 'reverse_string' with a single string argument
result = remote_server.reverse_string('Hello, World!')

print "Server answered:", result
