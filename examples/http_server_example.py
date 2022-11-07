#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gevent
import gevent.wsgi
import gevent.queue
from aiotinyrpc.protocols.jsonrpc import JSONRPCProtocol
from aiotinyrpc.transports.wsgi import WsgiServerTransport
from aiotinyrpc.server.gevent import RPCServerGreenlets
from aiotinyrpc.dispatch import RPCDispatcher

dispatcher = RPCDispatcher()
transport = WsgiServerTransport(queue_class=gevent.queue.Queue)

# start wsgi server as a background-greenlet
wsgi_server = gevent.wsgi.WSGIServer(("127.0.0.1", 5000), transport.handle)
gevent.spawn(wsgi_server.serve_forever)

rpc_server = RPCServerGreenlets(transport, JSONRPCProtocol(), dispatcher)


@dispatcher.public
def reverse_string(s):
    return s[::-1]


# in the main greenlet, run our rpc_server
rpc_server.serve_forever()
