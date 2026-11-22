#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""claude_check.py 单元测试"""

import json
import socket
import unittest
from unittest import mock

import claude_check


class TestColors(unittest.TestCase):
    def setUp(self):
        self._orig = {attr: getattr(claude_check.Colors, attr)
                      for attr in ('GREEN', 'RED', 'YELLOW', 'BLUE', 'CYAN',
                                   'MAGENTA', 'DIM', 'BOLD', 'RESET')}

    def tearDown(self):
        for attr, val in self._orig.items():
            setattr(claude_check.Colors, attr, val)

    def test_disable_clears_all(self):
        claude_check.Colors.disable()
        for attr in self._orig:
            self.assertEqual(getattr(claude_check.Colors, attr), '')


class TestCheckIPv6(unittest.TestCase):
    @mock.patch('claude_check.socket.has_ipv6', False)
    def test_no_ipv6_support(self):
        connected, addr = claude_check._check_ipv6()
        self.assertFalse(connected)
        self.assertIsNone(addr)

    @mock.patch('claude_check.socket.has_ipv6', True)
    @mock.patch('claude_check.socket.socket')
    def test_ipv6_connected(self, mock_sock_cls):
        mock_sock = mock.MagicMock()
        mock_sock.getsockname.return_value = ('2001:db8::1', 0, 0, 0)
        mock_sock_cls.return_value = mock_sock
        connected, addr = claude_check._check_ipv6()
        self.assertTrue(connected)
        self.assertEqual(addr, '2001:db8::1')
        mock_sock.close.assert_called_once()

    @mock.patch('claude_check.socket.has_ipv6', True)
    @mock.patch('claude_check.socket.socket')
    def test_ipv6_unreachable(self, mock_sock_cls):
        mock_sock = mock.MagicMock()
        mock_sock.connect.side_effect = OSError('unreachable')
        mock_sock_cls.return_value = mock_sock
        connected, addr = claude_check._check_ipv6()
        self.assertFalse(connected)
        self.assertIsNone(addr)
        mock_sock.close.assert_called_once()


class TestTrustScore(unittest.TestCase):
    def _base_results(self):
        return {
            'ipv6': {'connected': False},
            'dns_leak': {'status': 'safe'},
            'ip_quality': {
                'status': 'ok',
                'hosting': False,
                'proxy': False,
                'timezone_match': True,
                'lang_match': True,
            },
            'cf_trace': {'status': 'ok', 'ip_consistent': True},
            'cloudflare_waf': {'status': 'pass'},
            'api_connectivity': {'status': 'reachable'},
        }

    def test_perfect_score(self):
        score, details = claude_check.calculate_trust_score(self._base_results())
        self.assertEqual(score, 100)
        for v in details.values():
            self.assertEqual(v, 0)

    def test_ipv6_leak_deducts_20(self):
        r = self._base_results()
        r['ipv6']['connected'] = True
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 80)
        self.assertEqual(details['ipv6'], -20)

    def test_dns_leak_deducts_20(self):
        r = self._base_results()
        r['dns_leak']['status'] = 'leaked'
        score, _ = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 80)

    def test_hosting_ip_deducts_15(self):
        r = self._base_results()
        r['ip_quality']['hosting'] = True
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 85)
        self.assertEqual(details['ip_type'], -15)

    def test_timezone_mismatch_deducts_15(self):
        r = self._base_results()
        r['ip_quality']['timezone_match'] = False
        score, _ = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 85)

    def test_lang_mismatch_deducts_5(self):
        r = self._base_results()
        r['ip_quality']['lang_match'] = False
        score, _ = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 95)

    def test_ip_inconsistency_deducts_10(self):
        r = self._base_results()
        r['cf_trace']['ip_consistent'] = False
        score, _ = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 90)

    def test_waf_blocked_deducts_15(self):
        r = self._base_results()
        r['cloudflare_waf']['status'] = 'blocked'
        score, _ = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 85)

    def test_browser_challenge_deducts_0(self):
        r = self._base_results()
        r['cloudflare_waf']['status'] = 'browser_challenge'
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 100)
        self.assertEqual(details['waf'], 0)

    def test_browser_pass_overrides_curl_challenge(self):
        r = self._base_results()
        r['cloudflare_waf']['status'] = 'js_challenge'
        r['browser_waf'] = {'status': 'pass'}
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 100)
        self.assertEqual(details['waf'], 0)

    def test_browser_blocked_deducts_15(self):
        r = self._base_results()
        r['cloudflare_waf']['status'] = 'browser_challenge'
        r['browser_waf'] = {'status': 'blocked'}
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 85)
        self.assertEqual(details['waf'], -15)

    def test_webrtc_leak_deducts_15(self):
        r = self._base_results()
        r['webrtc'] = {'status': 'leaked'}
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 85)
        self.assertEqual(details['webrtc'], -15)

    def test_trace_drift_deducts_5(self):
        r = self._base_results()
        r['cf_trace']['stable'] = False
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 95)
        self.assertEqual(details['trace_stability'], -5)

    def test_abuse_deducts_5(self):
        r = self._base_results()
        r['reputation'] = {'status': 'ok', 'abuse_count': 7}
        score, details = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 95)
        self.assertEqual(details['abuse'], -5)

    def test_api_banned_deducts_15(self):
        r = self._base_results()
        r['api_connectivity']['status'] = 'hard_banned'
        score, _ = claude_check.calculate_trust_score(r)
        self.assertEqual(score, 85)

    def test_everything_bad(self):
        r = {
            'ipv6': {'connected': True},                          # -20
            'dns_leak': {'status': 'leaked'},                     # -20
            'ip_quality': {
                'status': 'ok',
                'hosting': True,                                  # -15
                'proxy': True,
                'timezone_match': False,                          # -15
                'lang_match': False,                              # -5
            },
            'cf_trace': {'status': 'ok', 'ip_consistent': False}, # -10
            'cloudflare_waf': {'status': 'blocked'},              # -15
            'api_connectivity': {'status': 'hard_banned'},        # -15
        }
        score, _ = claude_check.calculate_trust_score(r)
        # -20-20-15-15-5-10-15-15 = -115, clamped to 0
        self.assertEqual(score, 0)

    def test_score_never_negative(self):
        r = self._base_results()
        r['ipv6']['connected'] = True
        r['dns_leak']['status'] = 'leaked'
        r['ip_quality']['hosting'] = True
        r['ip_quality']['timezone_match'] = False
        r['cloudflare_waf']['status'] = 'blocked'
        r['api_connectivity']['status'] = 'hard_banned'
        score, _ = claude_check.calculate_trust_score(r)
        self.assertGreaterEqual(score, 0)


class TestCalculateRisk(unittest.TestCase):
    def _base_results(self):
        return {
            'ipv6': {'connected': False},
            'dns_leak': {'status': 'safe'},
            'ip_quality': {
                'status': 'ok',
                'hosting': False,
                'proxy': False,
                'timezone_match': True,
                'lang_match': True,
            },
            'cf_trace': {'status': 'ok', 'ip_consistent': True},
            'cloudflare_waf': {'status': 'pass'},
            'api_connectivity': {'status': 'reachable'},
        }

    def test_all_safe_is_low(self):
        level, suggestions = claude_check.calculate_risk(self._base_results())
        self.assertEqual(level, 'LOW')
        self.assertEqual(suggestions, [])

    def test_ipv6_leak_is_high(self):
        r = self._base_results()
        r['ipv6']['connected'] = True
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')

    def test_hosting_ip_is_medium(self):
        r = self._base_results()
        r['ip_quality']['hosting'] = True
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'MEDIUM')

    def test_lang_mismatch_is_medium(self):
        r = self._base_results()
        r['ip_quality']['lang_match'] = False
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'MEDIUM')

    def test_ip_inconsistency_is_medium(self):
        r = self._base_results()
        r['cf_trace']['ip_consistent'] = False
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'MEDIUM')

    def test_multiple_reds_is_critical(self):
        r = self._base_results()
        r['ipv6']['connected'] = True
        r['dns_leak']['status'] = 'leaked'
        level, suggestions = claude_check.calculate_risk(r)
        self.assertEqual(level, 'CRITICAL')
        self.assertTrue(len(suggestions) >= 2)

    def test_timezone_mismatch(self):
        r = self._base_results()
        r['ip_quality']['timezone_match'] = False
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')

    def test_waf_blocked(self):
        r = self._base_results()
        r['cloudflare_waf']['status'] = 'blocked'
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')

    def test_browser_challenge_is_low_with_note(self):
        # curl 被挑战是默认行为，不构成风险等级，只给提示
        r = self._base_results()
        r['cloudflare_waf']['status'] = 'browser_challenge'
        level, suggestions = claude_check.calculate_risk(r)
        self.assertEqual(level, 'LOW')
        self.assertTrue(any('浏览器' in s for s in suggestions))

    def test_browser_blocked_is_high(self):
        r = self._base_results()
        r['browser_waf'] = {'status': 'blocked'}
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')

    def test_webrtc_leak_is_high(self):
        r = self._base_results()
        r['webrtc'] = {'status': 'leaked'}
        level, suggestions = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')
        self.assertTrue(any('WebRTC' in s for s in suggestions))

    def test_trace_drift_is_medium(self):
        r = self._base_results()
        r['cf_trace']['stable'] = False
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'MEDIUM')

    def test_api_banned(self):
        r = self._base_results()
        r['api_connectivity']['status'] = 'hard_banned'
        level, _ = claude_check.calculate_risk(r)
        self.assertEqual(level, 'HIGH')


class TestScoreLabel(unittest.TestCase):
    def test_labels(self):
        _, label = claude_check._score_label(95)
        self.assertEqual(label, '极度纯净')
        _, label = claude_check._score_label(80)
        self.assertEqual(label, '纯净')
        _, label = claude_check._score_label(60)
        self.assertEqual(label, '良好')
        _, label = claude_check._score_label(30)
        self.assertEqual(label, '中性')
        _, label = claude_check._score_label(10)
        self.assertEqual(label, '危险')


class TestFmtOffset(unittest.TestCase):
    def test_positive(self):
        self.assertEqual(claude_check._fmt_offset(28800), 'UTC+8.0')

    def test_negative(self):
        self.assertEqual(claude_check._fmt_offset(-18000), 'UTC-5.0')

    def test_zero(self):
        self.assertEqual(claude_check._fmt_offset(0), 'UTC+0.0')


class TestGetSystemLang(unittest.TestCase):
    @mock.patch.dict('os.environ', {'LANG': 'en_US.UTF-8'})
    def test_from_lang_env(self):
        self.assertEqual(claude_check._get_system_lang(), 'en')

    @mock.patch.dict('os.environ', {'LANG': 'zh_CN.UTF-8'})
    def test_chinese(self):
        self.assertEqual(claude_check._get_system_lang(), 'zh')

    @mock.patch.dict('os.environ', {'LANG': '', 'LANGUAGE': 'ja_JP'})
    def test_from_language_env(self):
        self.assertEqual(claude_check._get_system_lang(), 'ja')


class TestCheckIpAttributes(unittest.TestCase):
    """IP 质量检测应以 Claude 实际出口 (cf trace) 为参照。"""

    def _auto_data(self):
        # 本机默认路由出口：美国 LA (UTC-8)
        return {
            'status': 'success',
            'query': '216.36.103.166',
            'country': 'United States', 'countryCode': 'US', 'city': 'Los Angeles',
            'isp': 'GTT', 'as': 'AS3257',
            'hosting': False, 'proxy': False,
            'timezone': 'America/Los_Angeles', 'offset': -28800,
        }

    def _sg_data(self, ip):
        # Claude 实际出口：新加坡家宽 (UTC+8)
        return {
            'status': 'success',
            'query': ip,
            'country': 'Singapore', 'countryCode': 'SG', 'city': 'Singapore',
            'isp': 'Singtel', 'as': 'AS9506',
            'hosting': False, 'proxy': False,
            'timezone': 'Asia/Singapore', 'offset': 28800,
        }

    @mock.patch('builtins.print')
    def test_reference_uses_cf_trace_ip(self, mock_print):
        with mock.patch.object(claude_check, '_query_ipapi') as q:
            q.side_effect = lambda ip=None: (
                self._auto_data() if ip is None else self._sg_data(ip))
            results = {
                'cf_trace': {'status': 'ok', 'ip': '116.14.13.40'},
                'timezone': {'local_offset': 28800},
                'system_lang': 'en',
            }
            claude_check.check_ip_attributes(results)

        q.assert_any_call('116.14.13.40')
        ip_q = results['ip_quality']
        self.assertEqual(ip_q['ip'], '116.14.13.40')
        self.assertEqual(ip_q['reference'], 'cloudflare_trace')
        # 对照 Claude 视角的新加坡出口：时区/语言均匹配
        self.assertTrue(ip_q['timezone_match'])
        self.assertTrue(ip_q['lang_match'])
        self.assertFalse(ip_q['hosting'])
        # 默认出口与 Claude 出口不同 -> 分流提示，但不算泄漏异常
        self.assertFalse(results['cf_trace']['ip_consistent'])

    @mock.patch('builtins.print')
    def test_fallback_to_default_exit(self, mock_print):
        with mock.patch.object(claude_check, '_query_ipapi') as q:
            q.side_effect = lambda ip=None: self._auto_data()
            results = {
                'cf_trace': {'status': 'error', 'ip': None},
                'timezone': {'local_offset': -28800},
                'system_lang': 'en',
            }
            claude_check.check_ip_attributes(results)

        q.assert_called_once()
        ip_q = results['ip_quality']
        self.assertEqual(ip_q['ip'], '216.36.103.166')
        self.assertEqual(ip_q['reference'], 'default_exit')
        self.assertTrue(ip_q['timezone_match'])
        self.assertIsNone(results['cf_trace']['ip_consistent'])

    @mock.patch('builtins.print')
    def test_trace_query_failure_falls_back(self, mock_print):
        with mock.patch.object(claude_check, '_query_ipapi') as q:
            q.side_effect = lambda ip=None: (
                self._auto_data() if ip is None else None)
            results = {
                'cf_trace': {'status': 'ok', 'ip': '116.14.13.40'},
                'timezone': {'local_offset': -28800},
                'system_lang': 'en',
            }
            claude_check.check_ip_attributes(results)

        ip_q = results['ip_quality']
        self.assertEqual(ip_q['ip'], '216.36.103.166')
        self.assertEqual(ip_q['reference'], 'default_exit')

    @mock.patch('builtins.print')
    def test_default_exit_equals_cf_ip(self, mock_print):
        with mock.patch.object(claude_check, '_query_ipapi') as q:
            q.side_effect = lambda ip=None: self._auto_data()
            results = {
                'cf_trace': {'status': 'ok', 'ip': '216.36.103.166'},
                'timezone': {'local_offset': -28800},
                'system_lang': 'en',
            }
            claude_check.check_ip_attributes(results)

        q.assert_called_once()  # IP 相同时无需二次查询
        self.assertTrue(results['cf_trace']['ip_consistent'])


class TestParseArgs(unittest.TestCase):
    @mock.patch('sys.argv', ['claude_check.py'])
    def test_defaults(self):
        args = claude_check.parse_args()
        self.assertFalse(args.skip_api)
        self.assertFalse(args.skip_web)
        self.assertFalse(args.json_output)
        self.assertFalse(args.no_color)

    @mock.patch('sys.argv', ['claude_check.py', '--json', '--skip-api', '--skip-web', '--no-color'])
    def test_all_flags(self):
        args = claude_check.parse_args()
        self.assertTrue(args.skip_api)
        self.assertTrue(args.skip_web)
        self.assertTrue(args.json_output)
        self.assertTrue(args.no_color)


if __name__ == '__main__':
    unittest.main()
