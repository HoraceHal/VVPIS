import base64
import hashlib
import io
import json
import pathlib
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
from vvpis import config
from vvpis.bridge import Bridge
from vvpis.fetch import extract_safe
from vvpis.health import restart_allowed


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.state = config.new_state('vpn.example.com', '8.8.4.4')

    def test_independent_credentials(self):
        other = config.new_state('vpn.example.com', '8.8.4.4')
        for name in ['password', 'sub_id', 'trojan_password', 'hmac_secret', 'stats_secret', 'controller_secret']:
            self.assertNotEqual(self.state[name], other[name])
        self.assertEqual(len(self.state['sub_id']), 48)

    def test_reject_injection_and_private_addresses(self):
        for value in ['127.0.0.1', '10.0.0.2', '::1', 'example.com;whoami', '$(whoami).com',
                      'good.example\nbad', '-bad.example', 'https://example.com', 'a..com']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                config.host_name(value)

    def test_native_frontend_and_statistics(self):
        settings = config.xui_settings(self.state)
        self.assertEqual(settings['subThemeDir'], '')
        self.assertEqual(settings['subProfileMode'], 'builtin')
        template = json.loads(settings['xrayTemplateConfig'])
        self.assertIn('StatsService', template['api']['services'])
        self.assertTrue(template['policy']['levels']['0']['statsUserUplink'])
        self.assertEqual(template['routing']['rules'][0]['outboundTag'], 'api')
        self.assertTrue(all(i['listen'] == '127.0.0.1' for i in template['inbounds']))
        client = json.loads(config.inbound(self.state)['settings'])['clients'][0]
        self.assertEqual((client['totalGB'], client['expiryTime']), (0, 0))

    def test_no_credentials_in_public_nginx_configuration(self):
        rendered = config.nginx(self.state)
        for key in ['password', 'trojan_password', 'hmac_secret', 'stats_secret', 'gateway_password']:
            self.assertNotIn(self.state[key], rendered)
        self.assertIn('127.0.0.1:25103', rendered)
        self.assertIn('proxy_protocol', rendered)
        self.assertNotIn('listen 25103', rendered)
        self.assertIn('immutable', rendered)
        self.assertIn('no-store', rendered)

    def test_gateway_private_network_block_and_modes(self):
        direct = config.gateway(self.state)
        self.assertEqual(direct['rules'][-1], 'MATCH,DIRECT')
        self.assertIn('IP-CIDR,169.254.0.0/16,REJECT', direct['rules'])
        self.assertFalse(direct['allow-lan'])
        hybrid = config.gateway(dict(self.state, airport_url='https://example.com/provider', mode='hybrid'))
        self.assertEqual(hybrid['rules'][-1], 'MATCH,SERVER-FIRST')
        group = next(g for g in hybrid['proxy-groups'] if g['name'] == 'SERVER-FIRST')
        self.assertEqual(group['proxies'], ['DIRECT', 'AIRPORT'])
        self.assertEqual(hybrid['proxy-providers']['backup']['interval'], 21600)

    def test_certificate_and_socks_authentication(self):
        h = config.hysteria(self.state)
        self.assertEqual(h['auth']['type'], 'http')
        self.assertEqual(h['trafficStats']['listen'], '127.0.0.1:25106')
        self.assertTrue(h['ignoreClientBandwidth'])
        self.assertEqual(h['congestion']['bbrProfile'], 'standard')
        self.assertEqual(h['outbounds'][0]['socks5']['password'], self.state['gateway_password'])


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = config.new_state('vpn.example.com', '8.8.4.4')
        self.bridge = Bridge(config.bridge_config(self.state), pathlib.Path(self.temp.name) / 'usage.db')
        self.sid = self.state['sub_id']
        self.info = dict(sId=self.sid, enabled=True, totalByte=0, expire=0,
                         uploadByte=10, downloadByte=100, links=['trojan://dummy@example.com'])
        self.bridge.info = lambda *args, **kwargs: dict(self.info)

    def tearDown(self):
        self.temp.cleanup()

    def test_authentication_and_disabled_quota_fail_closed(self):
        token = self.bridge.token(self.sid)
        identity = self.bridge.authenticate(token)
        self.assertEqual(identity, 'sub-' + hashlib.sha256(self.sid.encode()).hexdigest())
        self.assertIsNone(self.bridge.authenticate(token[:-1] + ('0' if token[-1] != '0' else '1')))
        self.info['enabled'] = False
        self.assertIsNone(self.bridge.authenticate(token))
        self.info.update(enabled=True, totalByte=1000)
        self.assertIsNone(self.bridge.authenticate(token))
        self.info.update(totalByte=0, expire=time.time() - 1)
        self.assertIsNone(self.bridge.authenticate(token))

    def test_usage_persists_without_double_counting_after_restarts(self):
        key = 'sub-' + hashlib.sha256(self.sid.encode()).hexdigest()
        self.bridge.record_traffic({key: {'tx': 10, 'rx': 100}}, 'epoch-1')
        self.bridge.record_traffic({key: {'tx': 10, 'rx': 100}}, 'epoch-1')
        self.assertEqual(self.bridge.usage(self.sid)['down'], 100)
        self.bridge.record_traffic({key: {'tx': 30, 'rx': 200}}, 'epoch-1')
        self.bridge.record_traffic({key: {'tx': 5, 'rx': 30}}, 'epoch-2')
        restarted = Bridge(config.bridge_config(self.state), self.bridge.state)
        restarted.record_traffic({key: {'tx': 5, 'rx': 30}}, 'epoch-2')
        self.assertEqual(restarted.usage(self.sid)['down'], 230)
        self.assertEqual(restarted.usage(self.sid)['up'], 35)
        self.assertEqual(restarted.usage('b' * 48)['down'], 0)

    def test_native_page_escapes_payload_and_includes_hysteria(self):
        page = dict(self.info, subTitle='</script><script>bad()</script>&')
        original = '<head><script>window.__SUB_PAGE_DATA__=' + json.dumps(page) + ';</script></head><div id="app"></div>'
        data, kind = self.bridge.transform(self.sid, '/sub/' + self.sid, original.encode(), 'text/html')
        text = data.decode()
        self.assertNotIn('<script>bad()', text)
        result, _ = json.JSONDecoder().raw_decode(text.split('window.__SUB_PAGE_DATA__=', 1)[1])
        self.assertEqual(result['subTitle'], page['subTitle'])
        self.assertEqual(len(result['links']), 2)
        self.assertIn('sni=vpn.example.com', result['links'][1])
        self.assertIn('<div id="app"></div>', text)

    def test_format_negotiation_and_browser_download(self):
        f = self.bridge.subscription_format
        path = '/sub/' + self.sid
        self.assertEqual(f(path, {}, 'Mozilla/5.0', 'text/html'), 'passthrough')
        self.assertEqual(f(path, {}, 'Quantumult%20X/1', '*/*'), 'qx')
        self.assertEqual(f(path, {}, 'Clash-Verge/2', '*/*'), 'mihomo')
        self.assertEqual(f(path, {}, 'Shadowrocket/2', '*/*'), 'raw')
        self.assertEqual(f('/clash/' + self.sid, {'view': ['raw']}, 'Mozilla', 'text/html'), 'mihomo')
        with self.assertRaises(ValueError):
            f(path, {'target': ['invalid']}, 'Mozilla')

    def test_export_profile_keeps_dns_inside_proxy(self):
        import yaml
        profile = {'proxies': [{'name': 'Trojan-TLS', 'type': 'trojan'}],
                   'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['Trojan-TLS']}], 'ipv6': True}
        body, _ = self.bridge.transform(self.sid, '/mihomo/' + self.sid,
                                       yaml.safe_dump(profile).encode(), 'application/yaml')
        output = yaml.safe_load(body)
        group = output['proxy-groups'][0]
        self.assertEqual(group['type'], 'fallback')
        self.assertEqual(group['proxies'], ['Hysteria2', 'Trojan-TLS'])
        self.assertFalse(output['ipv6'])
        self.assertTrue(all('#PROXY' in x for x in output['dns']['nameserver']))
        self.assertIn('tcp://any:53', output['tun']['dns-hijack'])
        self.assertFalse(output['proxies'][-1]['skip-cert-verify'])
        self.assertEqual(output['proxies'][-1]['sni'], 'vpn.example.com')


class SafetyTests(unittest.TestCase):
    def test_archive_traversal_and_links_rejected(self):
        for name, kind in [('../outside', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE), ('link', tarfile.SYMTYPE)]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                archive = pathlib.Path(tmp) / 'input.tar'
                with tarfile.open(archive, 'w') as tar:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                    tar.addfile(item, io.BytesIO(b''))
                with self.assertRaises(ValueError):
                    extract_safe(archive, pathlib.Path(tmp) / 'output')

    def test_restart_budget_and_cooldown(self):
        self.assertTrue(restart_allowed([], 10000))
        self.assertFalse(restart_allowed([9900], 10000))
        self.assertTrue(restart_allowed([9000], 10000))
        self.assertFalse(restart_allowed([8000, 9000], 10000))
        self.assertTrue(restart_allowed([1000, 2000], 10000))

    def test_manifest_requires_pinned_hashes(self):
        manifest = json.loads((pathlib.Path(__file__).resolve().parents[1] / 'versions.json').read_text())
        for name in ['xui', 'hysteria', 'mihomo']:
            self.assertNotIn('latest', manifest[name]['version'])
            for item in manifest[name]['assets'].values():
                self.assertRegex(item['sha256'], r'^[a-f0-9]{64}$')


if __name__ == '__main__':
    unittest.main()
