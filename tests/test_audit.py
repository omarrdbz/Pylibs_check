import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from oss_audit.__main__ import main
from oss_audit.core import (CSV_HEADERS, component, export,
                            license_risk, load_policy, scan_osv)
from oss_audit.resolvers import parse_assets, parse_npm, parse_pip


class AuditTests(unittest.TestCase):
    def test_policy_expressions(self):
        policy = load_policy('policies/licenses.json')
        self.assertEqual(license_risk('MIT OR GPL-3.0-only', policy), 'RISK')
        self.assertEqual(license_risk('MIT', policy), 'UNFLAGGED')
        self.assertEqual(license_risk('UNKNOWN', policy), 'UNKNOWN')
        policy['risky_patterns'] = ['MIT']
        self.assertEqual(license_risk('MIT', policy), 'RISK')

    def test_python_transitive_extras_and_markers(self):
        data = {'install': [
            {'requested': True, 'metadata': {'name': 'Root_Pkg', 'version': '1',
              'requires_dist': ['child[secure]', 'windows-only; sys_platform == "win32"']}},
            {'metadata': {'name': 'child', 'version': '2',
              'requires_dist': ['leaf; extra == "secure"']}},
            {'metadata': {'name': 'leaf', 'version': '3'}}],
            'environment': {'sys_platform': 'linux'}}
        components = parse_pip(data, 'Root_Pkg', None)
        self.assertEqual([c['dependency_type'] for c in components], ['ROOT', 'DIRECT', 'TRANSITIVE'])
        self.assertEqual(components[1]['dependencies'], [components[2]['purl']])

    def test_npm_multiple_versions_and_scoped_package(self):
        data = {'lockfileVersion': 3, 'packages': {
            '': {'dependencies': {'@scope/a': '1', 'b': '1'}},
            'node_modules/@scope/a': {'version': '1', 'dependencies': {'b': '2'}},
            'node_modules/b': {'version': '1'},
            'node_modules/@scope/a/node_modules/b': {'version': '2'}}}
        result = parse_npm(data, False)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]['dependencies'], ['pkg:npm/b@2'])
        self.assertEqual(result[2]['dependency_type'], 'TRANSITIVE')
        self.assertEqual(result[0]['purl'], 'pkg:npm/%40scope/a@1')

    def test_nuget_framework_union(self):
        data = {'targets': {'net8.0': {
            'Root/1.0.0': {'type': 'package', 'dependencies': {'Leaf': '2.0.0'}},
            'Leaf/2.0.0': {'type': 'package'}}},
            'project': {'frameworks': {'net8.0': {'dependencies': {'Root': {}}}}}}
        result = parse_assets(data, True)
        self.assertEqual([c['dependency_type'] for c in result], ['ROOT', 'DIRECT'])
        self.assertEqual(result[0]['dependencies'], ['pkg:nuget/leaf@2.0.0'])

    def test_osv_pagination_and_affected_fix_filter(self):
        c = component('PyPI', 'foo', '1')
        v = {'id': 'OSV-1', 'severity': [{'type': 'CVSS_V3', 'score': 'CVSS:3.1/example'}],
             'affected': [{'package': {'name': 'foo', 'ecosystem': 'PyPI'},
                           'ranges': [{'type': 'ECOSYSTEM', 'events': [{'fixed': '2'}]}]},
                          {'package': {'name': 'other', 'ecosystem': 'PyPI'},
                           'ranges': [{'events': [{'fixed': '99'}]}]}]}
        with tempfile.TemporaryDirectory() as tmp, patch('oss_audit.core.fetch', side_effect=[
                {'vulns': [v], 'next_page_token': 'next'}, {'vulns': [v, {'id': 'withdrawn', 'withdrawn': 'yes'}]}]) as fetch:
            scan_osv(c, Path(tmp))
            self.assertEqual(fetch.call_count, 2)
            self.assertEqual(len(c['vulnerabilities']), 1)
            self.assertEqual(c['vulnerabilities'][0]['fixed_versions'], ['2'])

    def test_outage_not_clean(self):
        c = component('npm', 'foo', '1')
        with tempfile.TemporaryDirectory() as tmp, patch('oss_audit.core.fetch', side_effect=OSError('offline')):
            scan_osv(c, Path(tmp))
        self.assertIn('offline', c['errors'][0])

    def test_nuget_osv_preserves_registry_case(self):
        c = component('NuGet', 'Newtonsoft.Json', '12.0.1')
        with tempfile.TemporaryDirectory() as tmp, patch('oss_audit.core.fetch', return_value={}) as fetch:
            scan_osv(c, Path(tmp))
            self.assertEqual(fetch.call_args.args[1]['package']['name'], 'Newtonsoft.Json')
            self.assertEqual(c['purl'], 'pkg:nuget/newtonsoft.json@12.0.1')

    def test_project_direct_and_missing_dependency(self):
        data = {'install': [{'requested': True, 'metadata': {'name': 'a', 'version': '1'}}]}
        self.assertEqual(parse_pip(data, None, 'requirements.txt')[0]['dependency_type'], 'DIRECT')
        data['install'][0]['metadata']['requires_dist'] = ['missing']
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            parse_pip(data, None, 'requirements.txt')

    def test_npm_incomplete_graph_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unresolved'):
            parse_npm({'lockfileVersion': 3, 'packages': {'': {'dependencies': {'missing': '1'}}}}, True)

    def test_report_csv_compatibility(self):
        c = component('npm', 'foo', '1', 'MIT')
        report = {'id': '11111111-1111-4111-8111-111111111111', 'evaluated_at': '2026-09-24T00:00:00Z',
                  'ecosystem': 'npm', 'target': 'foo', 'status': 'complete', 'components': [c]}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            export(report, path)
            with (path / 'audit_report.csv').open(encoding='utf-8-sig', newline='') as stream:
                self.assertEqual(next(csv.reader(stream)), CSV_HEADERS)

    def test_osv_error_continues_other_components(self):
        components = [component('PyPI', 'a', '1'), component('PyPI', 'b', '1')]
        def scan(c, path):
            if c['name'] == 'a':
                c['errors'].append('OSV unavailable')
        with tempfile.TemporaryDirectory() as tmp, patch('oss_audit.__main__.RESOLVERS',
                {'PyPI': lambda *args: components}), patch('oss_audit.__main__.scan_osv', side_effect=scan) as scanner:
            self.assertEqual(main(['evaluate', '--ecosystem', 'PyPI', '--target', 'a', '--output', tmp]), 2)
            self.assertEqual(scanner.call_count, 2)

    def test_failure_still_exports(self):
        with tempfile.TemporaryDirectory() as tmp, patch('oss_audit.__main__.RESOLVERS',
                {'PyPI': lambda *args: (_ for _ in ()).throw(ValueError('bad resolution'))}):
            result = main(['evaluate', '--ecosystem', 'PyPI', '--target', 'foo', '--output', tmp])
            self.assertEqual(result, 2)
            report = json.loads(next(Path(tmp).glob('*/evaluation.json')).read_text())
            self.assertEqual(report['status'], 'incomplete')
            self.assertEqual(report['decision'], 'pending')
            self.assertTrue(next(Path(tmp).glob('*/audit_report.csv')).exists())

    def test_findings_do_not_fail_or_approve(self):
        c = component('PyPI', 'foo', '1', 'GPL-3.0-only')
        c['vulnerabilities'] = [{'id': 'OSV-1', 'severity': [], 'severity_labels': [],
                                 'fixed_versions': [], 'url': 'https://osv.dev/vulnerability/OSV-1'}]
        with tempfile.TemporaryDirectory() as tmp, patch('oss_audit.__main__.RESOLVERS',
                {'PyPI': lambda *args: [c]}), patch('oss_audit.__main__.scan_osv'):
            self.assertEqual(main(['evaluate', '--ecosystem', 'PyPI', '--target', 'foo', '--output', tmp]), 0)
            report = json.loads(next(Path(tmp).glob('*/evaluation.json')).read_text())
            self.assertEqual(report['decision'], 'pending')
            self.assertEqual(report['components'][0]['license_risk'], 'RISK')


if __name__ == '__main__':
    unittest.main()
