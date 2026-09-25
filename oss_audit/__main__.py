import argparse
import json
import os
import platform
import sys
import tempfile
import uuid
from pathlib import Path

from .core import (export, license_risk, load_policy, now,
                   scan_osv, write_json)
from .resolvers import RESOLVERS


def evaluate(args):
    evaluation_id = str(uuid.uuid4())
    directory = Path(args.output).resolve() / evaluation_id
    evidence = directory / 'evidence'
    evidence.mkdir(parents=True)
    report = dict(schema_version=1, id=evaluation_id, evaluated_at=now(), ecosystem=args.ecosystem,
                  target=args.project or args.target, status='complete', decision='pending',
                  components=[], errors=[], environment={'python': sys.version, 'platform': platform.platform()},
                  pipeline={'build_id': os.getenv('BUILD_BUILDID'), 'commit': os.getenv('BUILD_SOURCEVERSION')})
    try:
        policy = load_policy(args.policy)
        report['policy'] = policy
        write_json(evidence / 'license-policy.json', policy)
        with tempfile.TemporaryDirectory(prefix='oss-assessment-') as temp:
            report['components'] = RESOLVERS[args.ecosystem](args.target, args.project, Path(temp), evidence, args.framework)
        if not report['components']:
            raise ValueError('Resolver returned no components')
        for c in report['components']:
            print(f'Assessing {c["purl"]}', flush=True)
            c['license_risk'] = license_risk(c['license'], policy)
            scan_osv(c, evidence)
            if c['errors']:
                report['status'] = 'incomplete'
    except Exception as exc:
        report['status'] = 'incomplete'
        report['errors'].append(str(exc))
    export(report, directory)
    print(json.dumps({'evaluation_id': evaluation_id, 'status': report['status'],
                      'decision': 'pending', 'evidence': str(directory), 'errors': report['errors']}))
    return 0 if report['status'] == 'complete' else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description='OSS evidence for manual security review')
    commands = parser.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('evaluate')
    scan.add_argument('--ecosystem', choices=list(RESOLVERS), required=True)
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument('--target', help='PyPI requirement, npm name@version, or NuGet name@version')
    source.add_argument('--project', help='requirements.txt, package.json directory, or .csproj')
    scan.add_argument('--framework', default='net8.0')
    scan.add_argument('--policy', default=str(Path(__file__).resolve().parent.parent / 'policies/licenses.json'))
    scan.add_argument('--output', default='artifacts')
    args = parser.parse_args(argv)
    return evaluate(args)


if __name__ == '__main__':
    sys.exit(main())
