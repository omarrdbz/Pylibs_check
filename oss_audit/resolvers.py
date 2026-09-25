"""Resolve in temporary directories; never install evaluation tools into target graphs."""
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote

from packaging.markers import default_environment
from packaging.requirements import Requirement

from .core import component, fetch, normalize, write_json


def run(args, cwd, evidence, env=None):
    if args[0] == 'npm' and os.name == 'nt':
        npm = shutil.which('npm.cmd')
        cli = Path(npm).parent / 'node_modules/npm/bin/npm-cli.js' if npm else Path('missing')
        if not cli.is_file():
            raise RuntimeError('Cannot locate npm-cli.js beside npm.cmd')
        args = ['node', str(cli), *args[1:]]
    executable = shutil.which(str(args[0]))
    if not executable:
        raise RuntimeError(f'Required executable not found: {args[0]}')
    result = subprocess.run([executable, *map(str, args[1:])], cwd=cwd, env=env,
                            capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=900)
    index = len(list(evidence.glob('command-*.json')))
    write_json(evidence / f'command-{index}.json', dict(command=list(map(str, args)),
               exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr))
    if result.returncode:
        raise RuntimeError(f'{args[0]} failed ({result.returncode}); see command-{index}.json')
    return result.stdout


def classify(components, roots, package_mode):
    by_ref = {c['purl']: c for c in components}
    for ref in roots:
        if ref in by_ref:
            by_ref[ref]['dependency_type'] = 'ROOT' if package_mode else 'DIRECT'
    if package_mode:
        for ref in roots:
            for dep in by_ref[ref]['dependencies']:
                if dep in by_ref and dep not in roots:
                    by_ref[dep]['dependency_type'] = 'DIRECT'
    return components


def parse_pip(data, target, project):
    index, metadata, extras = {}, {}, {}
    for entry in data['install']:
        meta = entry['metadata']
        c = component('PyPI', meta['name'], meta['version'],
                      meta.get('license_expression') or meta.get('license') or 'UNKNOWN',
                      download_url=entry.get('download_info', {}).get('url', 'N/A'),
                      homepage=meta.get('home_page', 'N/A'))
        index[c['name']], metadata[c['name']] = c, meta
        extras[c['name']] = set(entry.get('requested_extras', []))
    roots = {normalize('PyPI', e['metadata']['name']) for e in data['install'] if e.get('requested')}
    if not project:
        requested = Requirement(target)
        extras.setdefault(normalize('PyPI', requested.name), set()).update(requested.extras)
    environment = {**default_environment(), **data.get('environment', {})}
    # Iterate to a fixed point: extras requested transitively activate further edges.
    changed = True
    while changed:
        changed = False
        for name, meta in metadata.items():
            for text in meta.get('requires_dist', []):
                req = Requirement(text)
                if req.marker and not any(req.marker.evaluate({**environment, 'extra': extra})
                                          for extra in {'', *extras[name]}):
                    continue
                dep = normalize('PyPI', req.name)
                if dep not in index:
                    raise ValueError(f'Unresolved Python dependency: {name} -> {dep}')
                if not req.extras.issubset(extras[dep]):
                    extras[dep].update(req.extras)
                    changed = True
                if index[dep]['purl'] not in index[name]['dependencies']:
                    index[name]['dependencies'].append(index[dep]['purl'])
    return classify(list(index.values()), {index[n]['purl'] for n in roots}, not project)


def python_resolve(target, project, work, evidence, framework):
    report = evidence / 'pip-report.json'
    # A dry run with wheels gives the resolver closure without executing package build hooks.
    args = [sys.executable, '-m', 'pip', '--isolated', 'install', '--dry-run', '--ignore-installed',
            '--only-binary=:all:', '--disable-pip-version-check', '--cache-dir', work / 'pip-cache',
            '--index-url', 'https://pypi.org/simple', '--report', report]
    if project:
        source = Path(project).resolve()
        if not source.is_file():
            raise ValueError('Python project input must be a requirements file')
        args.extend(['-r', source])
    else:
        Requirement(target)  # Reject options and malformed names before invoking pip.
        args.append(target)
    run(args, work, evidence)
    components = parse_pip(json.loads(report.read_text(encoding='utf-8')), target, project)
    for c in components:
        try:
            meta = fetch(f'https://pypi.org/pypi/{quote(c["name"], safe="")}/{quote(c["version"], safe="")}/json')
            write_json(evidence / f'pypi-{c["name"]}-{c["version"]}.json', meta)
            info = meta['info']
            c['license'] = info.get('license_expression') or info.get('license') or c['license']
            if c['license'] == 'UNKNOWN':
                declared = [v.rsplit(' :: ', 1)[-1] for v in info.get('classifiers', [])
                            if v.startswith('License ::') and v.count(' :: ') > 1]
                c['license'] = ' OR '.join(declared) or 'UNKNOWN'
            uploads = [u['upload_time_iso_8601'] for u in meta.get('urls', []) if u.get('upload_time_iso_8601')]
            c['last_updated'] = max(uploads) if uploads else 'N/A'
        except Exception as exc:
            c['errors'].append(f'PyPI metadata: {exc}')
    return components


def parse_npm(data, package_mode):
    if data.get('lockfileVersion', 0) < 2:
        raise ValueError('npm lockfileVersion >= 2 required')
    packages = data['packages']
    locations, unique = {}, {}
    for location, meta in packages.items():
        if not location:
            continue
        if meta.get('link') or not meta.get('version'):
            raise ValueError(f'Unsupported workspace/link dependency: {location}')
        name = meta.get('name') or location.rsplit('node_modules/', 1)[-1]
        license = meta.get('license', 'UNKNOWN')
        if isinstance(license, dict):
            license = license.get('type', 'UNKNOWN')
        c = component('npm', name, meta['version'], license,
                      download_url=meta.get('resolved', 'N/A'))
        locations[location] = unique.setdefault(c['purl'], c)

    def resolve(location, name):
        base = location
        while True:
            candidate = f'{base}/node_modules/{name}' if base else f'node_modules/{name}'
            if candidate in locations:
                return locations[candidate]['purl']
            if not base:
                return None
            base = base.rsplit('/node_modules/', 1)[0] if '/node_modules/' in base else ''

    roots = set()
    for location, meta in packages.items():
        dependencies = {**meta.get('dependencies', {}), **meta.get('optionalDependencies', {}),
                        **meta.get('peerDependencies', {})}
        if location == '':
            dependencies.update(meta.get('devDependencies', {}))
        for name in dependencies:
            ref = resolve(location, name)
            optional = name in meta.get('optionalDependencies', {}) or meta.get('peerDependenciesMeta', {}).get(name, {}).get('optional')
            if ref is None:
                if optional:
                    continue
                raise ValueError(f'Unresolved npm dependency: {location} -> {name}')
            if location:
                locations[location]['dependencies'].append(ref)
            else:
                roots.add(ref)
    return classify(list(unique.values()), roots, package_mode)


def npm_resolve(target, project, work, evidence, framework):
    if project:
        source = Path(project).resolve()
        source = source.parent if source.is_file() else source
        for name in ('package.json', 'package-lock.json', 'npm-shrinkwrap.json'):
            if (source / name).exists():
                shutil.copy2(source / name, work / name)
        if not (work / 'package.json').exists():
            raise ValueError('package.json missing')
    else:
        if not re.fullmatch(r'(?:@[a-z0-9._-]+/)?[a-z0-9._-]+(?:@[^\s]+)?', target) or target.startswith('-'):
            raise ValueError('Expected registry package name[@version]')
        write_json(work / 'package.json', {'name': 'oss-assessment', 'version': '1.0.0', 'private': True})
    args = ['npm', 'install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund']
    args.extend(['--cache', str(work / 'npm-cache'), '--registry', 'https://registry.npmjs.org'])
    if not project:
        args.extend(['--save-exact', target])
    run(args, work, evidence)
    lock = work / ('npm-shrinkwrap.json' if (work / 'npm-shrinkwrap.json').exists() else 'package-lock.json')
    shutil.copy2(lock, evidence / lock.name)
    shutil.copy2(work / 'package.json', evidence / 'package.json')
    components = parse_npm(json.loads(lock.read_text(encoding='utf-8')), not project)
    for c in components:
        if c['license'] == 'UNKNOWN':
            try:
                meta = fetch(f'https://registry.npmjs.org/{quote(c["name"], safe="")}/{quote(c["version"], safe="")}')
                write_json(evidence / ('npm-' + c['name'].replace('/', '_') + '-' + c['version'] + '.json'), meta)
                license = meta.get('license', 'UNKNOWN')
                c['license'] = license.get('type', 'UNKNOWN') if isinstance(license, dict) else license
            except Exception as exc:
                c['errors'].append(f'npm metadata: {exc}')
    return components


def parse_assets(data, package_mode):
    unique, roots = {}, set()
    for framework, graph in data['targets'].items():
        index = {}
        for key, meta in graph.items():
            if meta.get('type') != 'package':
                if meta.get('type') == 'project':
                    raise ValueError('ProjectReference requires separate assessment of each project')
                continue
            name, version = key.rsplit('/', 1)
            c = component('NuGet', name, version)
            index[name.lower()] = unique.setdefault(c['purl'], c)
        tfm = framework.split('/')[0]
        direct = data['project']['frameworks'].get(tfm, {}).get('dependencies', {})
        roots.update(index[n.lower()]['purl'] for n in direct if n.lower() in index)
        for key, meta in graph.items():
            name = key.rsplit('/', 1)[0].lower()
            if name not in index:
                continue
            for dep in meta.get('dependencies', {}):
                if dep.lower() not in index:
                    raise ValueError(f'Unresolved NuGet dependency: {key} -> {dep}')
                index[name]['dependencies'].append(index[dep.lower()]['purl'])
    return classify(list(unique.values()), roots, package_mode)


def nuget_resolve(target, project, work, evidence, framework):
    packages = work / 'packages'
    env = {**os.environ, 'NUGET_PACKAGES': str(packages), 'DOTNET_CLI_HOME': str(work),
           'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
           'DOTNET_GENERATE_ASPNET_CERTIFICATE': 'false', 'DOTNET_ADD_GLOBAL_TOOLS_TO_PATH': 'false',
           'NUGET_HTTP_CACHE_PATH': str(work / 'nuget-cache')}
    if project:
        source = Path(project).resolve()
        if source.suffix != '.csproj':
            raise ValueError('NuGet project input must be a .csproj')
        dest = work / 'project'
        shutil.copytree(source.parent, dest, ignore=shutil.ignore_patterns('bin', 'obj', '.git', 'node_modules'))
        csproj = dest / source.name
    else:
        match = re.fullmatch(r'([A-Za-z0-9_.-]+)(?:@([A-Za-z0-9.+-]+))?', target)
        if not match or target.startswith('-'):
            raise ValueError('Expected NuGet package name[@version]')
        if not re.fullmatch(r'net[0-9]+\.[0-9]+', framework):
            raise ValueError('Expected target framework such as net8.0')
        csproj = work / 'assessment.csproj'
        root = ET.Element('Project', Sdk='Microsoft.NET.Sdk')
        ET.SubElement(ET.SubElement(root, 'PropertyGroup'), 'TargetFramework').text = framework
        ET.SubElement(ET.SubElement(root, 'ItemGroup'), 'PackageReference',
                      Include=match[1], Version=match[2] or '*')
        ET.ElementTree(root).write(csproj, encoding='utf-8', xml_declaration=True)
    config = work / 'NuGet.Config'
    config.write_text('<configuration><packageSources><clear />'
                      '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" />'
                      '</packageSources></configuration>', encoding='utf-8')
    run(['dotnet', 'restore', csproj, '--configfile', config, '--packages', packages, '-p:NuGetAudit=false',
         '-p:RestorePackagesWithLockFile=true'], work, evidence, env)
    asset_path = csproj.parent / 'obj' / 'project.assets.json'
    shutil.copy2(asset_path, evidence / 'project.assets.json')
    if (csproj.parent / 'packages.lock.json').exists():
        shutil.copy2(csproj.parent / 'packages.lock.json', evidence / 'packages.lock.json')
    components = parse_assets(json.loads(asset_path.read_text(encoding='utf-8')), not project)
    for c in components:
        files = list((packages / c['name'] / c['version'].lower()).glob('*.nuspec'))
        if not files:
            c['errors'].append('NuGet license metadata missing')
            continue
        shutil.copy2(files[0], evidence / (c['name'] + '-' + c['version'] + '.nuspec'))
        tree = ET.parse(files[0])
        package_id = tree.find('.//{*}id')
        if package_id is not None and package_id.text:
            c['query_name'] = package_id.text
        license = tree.find('.//{*}license')
        if license is not None:
            c['license'] = license.text if license.get('type') == 'expression' else 'SEE LICENSE FILE: ' + (license.text or '')
        else:
            # A URL is evidence, not a recognized license expression.
            url = tree.find('.//{*}licenseUrl')
            c['license_url'] = url.text if url is not None else None
    return components


RESOLVERS = {'PyPI': python_resolve, 'npm': npm_resolve, 'NuGet': nuget_resolve}
