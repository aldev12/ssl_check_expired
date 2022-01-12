import datetime
import ssl
import socket

import yaml
from dateutil import parser

default_port = '443'
haproxy_path = 'haproxy.yaml'
server_name_contains = ['google', 'yandex']


def check_ssl(addresses: set):
    context = ssl.create_default_context()
    for address in addresses:
        if isinstance(address, str):
            hostname = address
            port = default_port
        else:
            raise ValueError(f'Wrong address {address}, address should be str')
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    data = ssock.getpeercert()
                    date_expired = parser.parse(data['notAfter'])
                    today = datetime.datetime.now().replace(tzinfo=datetime.timezone.utc)
                    expired_after = (date_expired - today).days

                    if expired_after < 30:
                        print(f'ERROR: HOST - {hostname}; Not After {data["notAfter"]}')
                    elif expired_after < 60:
                        print(f'WARNING: HOST - {hostname}; Not After {data["notAfter"]}')

        except socket.gaierror:
            print(f'HOST - {hostname}; NOT ALLOWED')


def get_addresses():
    with open(haproxy_path, "r") as stream:
        try:
            yaml_data = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)
    _addresses = parse_addresses(yaml_data)
    return _addresses


def parse_addresses(data: dict) -> set:
    _addresses = set()
    for key, val in data.items():
        if isinstance(val, dict):
            _addresses |= parse_addresses(val)
        if key == 'server_names':
            _addresses |= set([v for v in val if any(n in v for n in server_name_contains)])
    return _addresses


if __name__ == '__main__':
    addresses = get_addresses()
    check_ssl(addresses)
