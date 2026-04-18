import socket


def _get_interface_ip(family, addr):
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(1.5)
            s.connect((addr, 53))
            return s.getsockname()[0]
    except Exception:
        return None


def get_default_interface_ipv4(addr="8.8.8.8"):
    return _get_interface_ip(socket.AF_INET, addr)


def get_default_interface_ipv6(addr="2001:4860:4860::8888"):
    return _get_interface_ip(socket.AF_INET6, addr)
