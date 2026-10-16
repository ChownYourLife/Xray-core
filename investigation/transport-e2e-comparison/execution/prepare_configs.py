#!/usr/bin/env python3
"""Common fixed-node configs and candidate relay configs; no production changes."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = Path('/Users/hosi/D/V2ray/Xray-core/investigation/transport-e2e-comparison')
CONFIG = ROOT / 'configs'
CONFIG.mkdir(exist_ok=True)
ID = 'b7ace7e7-6836-4ebd-b780-98993fad8791'
CASES = ['ssclassic-freedom', 'ss2022-freedom', 'ssclassic-wireguard', 'vless-wireguard', 'vmess-wireguard']
SS_METHOD = 'chacha20-ietf-poly1305'
SS2022_METHOD = '2022-blake3-aes-128-gcm'
SS2022_KEY = 'AAECAwQFBgcICQoLDA0ODw=='
PASSWORD = 'isolated-authorized-e2e-20261015'
SERVER_PRIVATE = 'EGs4lTSJPmgELx6YiJAmPR2meWi6bY+e9rTdCipSj10='
SERVER_PUBLIC = 'MmLJ5iHFVVBp7VsB0hxfpQ0wEzAbT2KQnpQpj0+RtBw='
CLIENT_PRIVATE = 'CPQSpgxgdQRZa5SUbT3HLv+mmDVHLW5YR/rQlzum/2I='
CLIENT_PUBLIC = 'osAMIyil18HeZXGGBDC9KpZoM+L2iGyXWVSYivuM9B0='

def base():
    return {'log': {'loglevel': 'warning'}, 'inbounds': [], 'outbounds': []}

def freedom(redirect=None):
    settings = {'finalRules': [{'action': 'allow'}]}
    if redirect:
        settings['redirect'] = redirect
    return {'tag': 'to-echo', 'protocol': 'freedom', 'settings': settings}

def save(name, config):
    (CONFIG / (name + '.json')).write_text(json.dumps(config, indent=2) + '\n')

gateway = base()
gateway['inbounds'] = [{'tag': 'from-wireguard', 'listen': '127.0.0.1', 'port': 19100,
    'protocol': 'wireguard', 'settings': {'secretKey': SERVER_PRIVATE, 'address': ['10.77.0.1/32'],
    'mtu': 1420, 'noKernelTun': True, 'peers': [{'publicKey': CLIENT_PUBLIC, 'allowedIPs': ['0.0.0.0/0', '::/0']}]}}]
gateway['outbounds'] = [freedom('127.0.0.1:19090')]
save('gateway', gateway)

for case in CASES:
    protocol = 'shadowsocks' if case.startswith('ss') else case.split('-')[0]
    is_wg = case.endswith('wireguard')
    destination = '10.77.0.1' if is_wg else '127.0.0.1'
    if protocol == 'shadowsocks':
        method = SS2022_METHOD if case.startswith('ss2022') else SS_METHOD
        password = SS2022_KEY if case.startswith('ss2022') else PASSWORD
        incoming = {'method': method, 'password': password, 'network': 'tcp,udp'}
        outgoing = {'servers': [{'address': '127.0.0.1', 'port': 19200, 'method': method, 'password': password}]}
    else:
        user = {'id': ID}
        incoming = {'clients': [user]}
        if protocol == 'vless':
            incoming['decryption'] = 'none'
            user = {'id': ID, 'encryption': 'none'}
        else:
            user = {'id': ID, 'security': 'chacha20-poly1305'}
        outgoing = {'vnext': [{'address': '127.0.0.1', 'port': 19200, 'users': [user]}]}
    relay = base()
    relay['inbounds'] = [{'tag': 'candidate-inbound-' + protocol, 'listen': '127.0.0.1', 'port': 19200,
                          'protocol': protocol, 'settings': incoming}]
    if is_wg:
        relay['outbounds'] = [{'tag': 'candidate-wireguard-outbound', 'protocol': 'wireguard',
            'settings': {'secretKey': CLIENT_PRIVATE, 'address': ['10.77.0.2/32'], 'mtu': 1420,
                         'noKernelTun': True, 'peers': [{'publicKey': SERVER_PUBLIC,
                         'endpoint': '127.0.0.1:19100', 'allowedIPs': ['10.77.0.1/32']}]}}]
    else:
        relay['outbounds'] = [freedom()]
    client = base()
    client['inbounds'] = [{'tag': 'application-entry', 'listen': '127.0.0.1', 'port': 19300,
        'protocol': 'dokodemo-door', 'settings': {'address': destination, 'port': 19090, 'network': 'tcp,udp'}}]
    client['outbounds'] = [{'tag': 'common-client-' + protocol, 'protocol': protocol,
                            'settings': outgoing, 'mux': {'enabled': False}}]
    save(case + '-relay', relay)
    save(case + '-client', client)
manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(CONFIG.glob('*.json'))}
(EVIDENCE / 'config-pins.json').write_text(json.dumps({'files': manifest,
    'matrix': [{'case': c, 'networks': ['tcp', 'udp'], 'route': 'application->fixed-client(' + c.split('-')[0] + ' outbound)->candidate-relay(' + c.split('-')[0] + ' inbound)->' + ('candidate-WG-outbound->fixed-WG-gateway->echo' if c.endswith('wireguard') else 'freedom->echo')} for c in CASES],
    'ports': {'application_echo': 19090, 'wireguard_gateway_udp': 19100, 'candidate_inbound': 19200, 'common_client_entry_tcp_udp': 19300},
    'wg_virtual_destination': '10.77.0.1:19090', 'wg_gateway_freedom_redirect': '127.0.0.1:19090',
    'classic_ss_method': SS_METHOD, 'ss2022_method': SS2022_METHOD,
    'fixed_node_binary': 'hybrid', 'candidate_node': 'relay only'}, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
