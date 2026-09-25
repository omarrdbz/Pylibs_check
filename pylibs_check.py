"""Backward-compatible Python entry point for the multiecosystem evaluator."""
import argparse
import re
import shutil
import sys
from pathlib import Path

from oss_audit.__main__ import main


def legacy_main(argv=None):
    parser = argparse.ArgumentParser(description='Evaluate a Python package for manual review')
    parser.add_argument('package')
    parser.add_argument('--output', default='artifacts')
    parser.add_argument('--policy', default=str(Path(__file__).parent / 'policies/licenses.json'))
    args = parser.parse_args(argv)
    output = Path(args.output)
    before = set(output.glob('*/audit_report.csv'))
    code = main(['evaluate', '--ecosystem', 'PyPI', '--target', args.package,
                 '--output', args.output, '--policy', args.policy])
    created = set(output.glob('*/audit_report.csv')) - before
    if len(created) == 1:
        slug = re.sub(r'[^A-Za-z0-9_.-]', '_', args.package.split('[')[0].split('=')[0])
        destination = Path(f'audit_report_{slug}.csv')
        try:
            shutil.copyfile(created.pop(), destination)
            print(f'Compatibility CSV: {destination.resolve()}')
        except OSError as exc:
            print(f'Cannot copy compatibility CSV: {exc}', file=sys.stderr)
            return 2
    return code


if __name__ == '__main__':
    sys.exit(legacy_main())
