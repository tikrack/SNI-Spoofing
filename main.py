import asyncio
import os
import socket
import sys
import json
import threading

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    return os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))


config = json.load(open(os.path.join(get_exe_dir(), "config.json"), "r"))

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]

INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)

DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

fake_injective_connections = {}


def tune(sock: socket.socket):
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)


async def pipe(src: socket.socket, dst: socket.socket):
    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await loop.sock_recv(src, 65536)
            if not data:
                break
            await loop.sock_sendall(dst, data)
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except:
            pass


async def handle(incoming_sock: socket.socket):
    loop = asyncio.get_running_loop()
    outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        tune(incoming_sock)
        tune(outgoing_sock)

        outgoing_sock.bind((INTERFACE_IPV4, 0))

        if DATA_MODE != "tls":
            return

        fake_data = ClientHelloMaker.get_client_hello_with(
            os.urandom(32),
            os.urandom(32),
            FAKE_SNI,
            os.urandom(32),
        )

        src_port = outgoing_sock.getsockname()[1]

        conn = FakeInjectiveConnection(
            outgoing_sock,
            INTERFACE_IPV4,
            CONNECT_IP,
            src_port,
            CONNECT_PORT,
            fake_data,
            BYPASS_METHOD,
            incoming_sock,
        )

        fake_injective_connections[conn.id] = conn

        await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))

        if BYPASS_METHOD != "wrong_seq":
            return

        try:
            await asyncio.wait_for(conn.t2a_event.wait(), 2)
            if conn.t2a_msg != "fake_data_ack_recv":
                return
        finally:
            conn.monitor = False
            fake_injective_connections.pop(conn.id, None)

        t1 = asyncio.create_task(pipe(incoming_sock, outgoing_sock))
        t2 = asyncio.create_task(pipe(outgoing_sock, incoming_sock))

        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)

    finally:
        for s in (incoming_sock, outgoing_sock):
            try:
                s.close()
            except:
                pass


async def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tune(server)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen()

    loop = asyncio.get_running_loop()

    while True:
        client, _ = await loop.sock_accept(server)
        asyncio.create_task(handle(client))


if __name__ == "__main__":
    flt = f"tcp and ((ip.SrcAddr == {INTERFACE_IPV4} and ip.DstAddr == {CONNECT_IP}) or (ip.SrcAddr == {CONNECT_IP} and ip.DstAddr == {INTERFACE_IPV4}))"
    injector = FakeTcpInjector(flt, fake_injective_connections)
    threading.Thread(target=injector.run, daemon=True).start()
    asyncio.run(main())
