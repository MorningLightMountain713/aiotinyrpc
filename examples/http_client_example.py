#!/usr/bin/env python
# -*- coding: utf-8 -*-

from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.transports.http import HttpPostClientTransport
from aiotinyrpc import RPCClient

rpc_client = RPCClient(
    JSONRPCProtocol(), HttpPostClientTransport("http://127.0.0.1:5000/")
)

remote_server = rpc_client.get_proxy()

# call a method called 'reverse_string' with a single string argument
result = remote_server.reverse_string("Hello, World!")

print("Server answered:", result)
