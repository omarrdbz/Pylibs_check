"""Shared evidence model, policy, OSV client and report export."""
import csv
import fnmatch
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

CSV_HEADERS = ['Package', 'Version', 'Dependency Type', 'License', 'Status',
               'Vulnerabilities', 'Last Updated', 'Download URL', 'Home Page']


def now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')


def normalize(ecosystem, name):
    return re.sub(r'[-_.]+', '-', name).lower() if ecosystem == 'PyPI' else name.lower()


def component(ecosystem, name, version, license='UNKNOWN', **kwargs):
    query_name = name if ecosystem == 'NuGet' else normalize(ecosystem, name)
    name = normalize(ecosystem, name)
    kind = {'PyPI': 'pypi', 'npm': 'npm', 'NuGet': 'nuget'}[ecosystem]
    return dict(ecosystem=ecosystem, name=name, query_name=query_name, version=version, license=license or 'UNKNOWN',
                purl=f'pkg:{kind}/{quote(name, safe="/")}@{quote(version, safe="")}',
                dependency_type='TRANSITIVE', dependencies=[], vulnerabilities=[],
                errors=[], **kwargs)


def fetch(url, payload=None, raw=False):
    for attempt in range(3):
        try:
            req = Request(url, data=json.dumps(payload).encode() if payload is not None else None,
                          headers={'Content-Type': 'application/json', 'User-Agent': 'pylibs-check/2'})
            with urlopen(req, timeout=30) as response:
                body = response.read()
            return body if raw else json.loads(body)
        except (HTTPError, URLError, TimeoutError) as exc:
            if isinstance(exc, HTTPError) and exc.code not in (429, 500, 502, 503, 504):
                raise
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


def license_risk(license, policy):
    if license.strip().upper() in ('UNKNOWN', 'N/A', 'NOASSERTION', '') or license.startswith('SEE LICENSE FILE:'):
        return 'UNKNOWN' if policy['unknown_requires_review'] else 'UNCLASSIFIED'
    # Conservatively flag any risky term, even in an OR or WITH expression.
    terms = re.split(r'\s+(?:AND|OR|WITH)\s+|[()]', license, flags=re.I)
    return 'RISK' if any(fnmatch.fnmatchcase(term.strip().lower(), pattern.lower())
                         for term in [license, *terms] for pattern in policy['risky_patterns']) else 'UNFLAGGED'


def load_policy(path):
    policy = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(policy.get('version'), str) or not isinstance(policy.get('risky_patterns'), list):
        raise ValueError('Policy requires version and risky_patterns')
    if not all(isinstance(p, str) and p for p in policy['risky_patterns']):
        raise ValueError('Policy patterns must be nonempty strings')
    if not isinstance(policy.get('unknown_requires_review'), bool):
        raise ValueError('Policy requires boolean unknown_requires_review')
    return policy


def scan_osv(c, evidence):
    query = {'package': {'name': c.get('query_name', c['name']), 'ecosystem': c['ecosystem']}, 'version': c['version']}
    pages, seen = [], set()
    try:
        while True:
            page = fetch('https://api.osv.dev/v1/query', query)
            pages.append(page)
            for v in page.get('vulns', []):
                if v.get('withdrawn') or any(x['id'] == v['id'] for x in c['vulnerabilities']):
                    continue
                affected = [a for a in v.get('affected', [])
                            if a.get('package', {}).get('ecosystem') == c['ecosystem']
                            and normalize(c['ecosystem'], a['package']['name']) == c['name']]
                severity = v.get('severity', []) + [s for a in affected for s in a.get('severity', [])]
                labels = [v.get('database_specific', {}).get('severity')] + [
                    a.get('ecosystem_specific', {}).get('severity') for a in affected]
                fixed = sorted({e['fixed'] for a in affected for r in a.get('ranges', [])
                                if r.get('type') != 'GIT' for e in r.get('events', []) if e.get('fixed')})
                c['vulnerabilities'].append(dict(id=v['id'], aliases=v.get('aliases', []),
                    severity=severity, severity_labels=[s for s in labels if s], fixed_versions=fixed,
                    summary=v.get('summary', ''), source='OSV',
                    url='https://osv.dev/vulnerability/' + quote(v['id'])))
            token = page.get('next_page_token')
            if not token:
                break
            if token in seen:
                raise ValueError('OSV repeated pagination token')
            seen.add(token)
            query['page_token'] = token
    except Exception as exc:
        c['errors'].append(f'OSV: {exc}')
    finally:
        key = hashlib.sha256(c['purl'].encode()).hexdigest()
        write_json(evidence / f'osv-{key}.json', {'component': c['purl'], 'pages': pages})


def safe_cell(value):
    value = str(value)
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value


def write_csv(path, headers, rows):
    with Path(path).open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.writer(stream)
        writer.writerow(headers)
        writer.writerows([[safe_cell(v) for v in row] for row in rows])


def export(report, directory):
    components = report['components']
    rows, details = [], []
    for c in components:
        status = []
        if c['vulnerabilities']:
            status.append('VULNERABLE')
        if c.get('license_risk') == 'RISK':
            status.append('RISKY LICENSE')
        if c.get('license_risk') == 'UNKNOWN':
            status.append('UNKNOWN LICENSE')
        if c['errors']:
            status.append('AUDIT FAILED')
        rows.append([c['name'], c['version'], c['dependency_type'], c['license'],
                     ', '.join(status) or 'OK', ', '.join(v['id'] for v in c['vulnerabilities']),
                     c.get('last_updated', 'N/A'), c.get('download_url', 'N/A'), c.get('homepage', 'N/A')])
        for v in c['vulnerabilities']:
            details.append([report['id'], c['ecosystem'], c['name'], c['version'],
                            c['dependency_type'], c['license'], v['id'],
                            json.dumps(v['severity']), ', '.join(v['severity_labels']),
                            ', '.join(v['fixed_versions']), v['url']])
    write_csv(directory / 'audit_report.csv', CSV_HEADERS, rows)
    write_csv(directory / 'vulnerabilities.csv', ['Evaluation ID', 'Ecosystem', 'Package', 'Version',
              'Dependency Type', 'License', 'Vulnerability', 'Severity vectors', 'Severity labels',
              'Fixed versions (source)', 'Source'], details)
    bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'serialNumber': 'urn:uuid:' + report['id'],
           'version': 1, 'metadata': {'timestamp': report['evaluated_at'],
           'properties': [{'name': 'pylibs_check:completeness', 'value': report['status']}]},
           'components': [], 'dependencies': []}
    for c in components:
        bom['components'].append({'type': 'library', 'bom-ref': c['purl'], 'name': c['name'],
            'version': c['version'], 'purl': c['purl'], 'licenses': [{'license': {'name': c['license']}}],
            'properties': [{'name': 'pylibs_check:dependency_type', 'value': c['dependency_type']}]})
        bom['dependencies'].append({'ref': c['purl'], 'dependsOn': sorted(set(c['dependencies']))})
    write_json(directory / 'sbom.cdx.json', bom)
    write_json(directory / 'evaluation.json', report)
    hashes = {str(p.relative_to(directory)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in directory.rglob('*') if p.is_file() and p.name != 'manifest.json'}
    write_json(directory / 'manifest.json', {'evaluation_id': report['id'], 'sha256': hashes})
