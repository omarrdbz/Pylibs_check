import subprocess
import sys
import os
import json
import csv
import re
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError
from datetime import datetime

# Configuration
TOOL_PACKAGES = {"pip", "setuptools", "wheel", "pip-audit", "pip-licenses", "pipdeptree"}
RISKY_LICENSES = ["GPL", "AGPL", "Commons Clause", "SSPL"]
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"

# URLs that pip-audit needs to reach for vulnerability checks
AUDIT_ENDPOINTS = {
    "OSV API": "https://api.osv.dev/v1/query",
    "PyPI JSON API": "https://pypi.org/pypi/pip/json",
}

class DependencyAuditor:
    def __init__(self, target_package):
        self.target_package = target_package
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.venv_dir = tempfile.mkdtemp(prefix="audit_venv_", dir=script_dir)
        self.python_exe = os.path.join(self.venv_dir, "Scripts", "python.exe") if os.name == 'nt' else os.path.join(self.venv_dir, "bin", "python")
        self.results = {}  # {package_name: {data}}

    @staticmethod
    def _normalize(name):
        """Normalize package name per PEP 503 (lowercase, collapse [-_.] to '-')."""
        return re.sub(r"[-_.]+", "-", name).strip().lower()

    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def check_audit_connectivity(self):
        """
        Test connectivity to the vulnerability databases that pip-audit uses.
        Aborts the process if any endpoint is unreachable.
        """
        self.log("Checking connectivity to vulnerability databases...")
        failed = []
        for name, url in AUDIT_ENDPOINTS.items():
            try:
                if "osv.dev" in url:
                    # OSV /v1/query only accepts POST — send a minimal valid query
                    body = json.dumps({"package": {"name": "pip", "ecosystem": "PyPI"}}).encode()
                    req = Request(url, data=body, method="POST")
                    req.add_header("Content-Type", "application/json")
                else:
                    req = Request(url, method="GET")
                with urlopen(req, timeout=10) as resp:
                    self.log(f"  [OK] {name} ({url}) — HTTP {resp.status}")
            except URLError as e:
                self.log(f"  [FAIL] {name} ({url}) — {e.reason}")
                failed.append((name, url, str(e.reason)))
            except Exception as e:
                self.log(f"  [FAIL] {name} ({url}) — {e}")
                failed.append((name, url, str(e)))

        if failed:
            self.log("")
            self.log("ERROR: Cannot reach the following vulnerability databases:")
            for name, url, reason in failed:
                self.log(f"  • {name}: {url}")
                self.log(f"    Reason: {reason}")
            self.log("")
            self.log("Aborting: audit results would be unreliable without database access.")
            sys.exit(1)

    def setup_environment(self):
        self.log(f"Creating isolated environment in {self.venv_dir}...")
        subprocess.run([sys.executable, "-m", "venv", self.venv_dir], check=True)

        self.log(f"Installing target package: {self.target_package}...")
        try:
            subprocess.run(
                [self.python_exe, "-m", "pip", "install", self.target_package],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            print(f"Error installing target package: {e.stderr.decode()}")
            sys.exit(1)

        self.log("Installing audit tools...")
        tools = ["pip-licenses", "pip-audit", "pipdeptree"]
        try:
            subprocess.run(
                [self.python_exe, "-m", "pip", "install"] + tools,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            print(f"Error installing audit tools: {e.stderr.decode()}")
            sys.exit(1)

    def get_install_report(self):
        """
        Ask pip's resolver what would be installed for the target package and
        return the parsed 'install' list from --report.
        """
        self.log("Collecting pip resolver install report...")
        report_path = os.path.join(self.venv_dir, "pip_install_report.json")
        cmd = [
            self.python_exe, "-m", "pip", "install",
            "--dry-run", "--ignore-installed", "--report", report_path,
            self.target_package
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            self.log("WARNING: Could not generate pip install report. Falling back to pipdeptree scope.")
            stderr_text = (result.stderr or "").strip()
            if stderr_text:
                self.log(f"  pip stderr: {stderr_text[:400]}")
            return []

        try:
            raw = Path(report_path).read_text(encoding="utf-8")
            data = json.loads(raw)
            install_entries = data.get("install", []) if isinstance(data, dict) else []
            return install_entries if isinstance(install_entries, list) else []
        except Exception as e:
            self.log(f"WARNING: Failed to parse pip install report: {e}")
            return []

    def get_dependency_tree(self):
        self.log("Analyzing dependency tree...")
        # Use -p to request ONLY the target package's tree (excludes audit-tool deps)
        target_bare = self.target_package.split('[')[0].split('=')[0].split('<')[0].split('>')[0].strip()
        cmd = [self.python_exe, "-m", "pipdeptree", "-p", target_bare, "--json-tree"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"[ERROR] Error parsing pipdeptree output:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
            return []

    def get_licenses(self):
        self.log("Scanning licenses...")
        # Access executable directly as python -m pip-licenses might not work
        pip_licenses_exe = os.path.join(os.path.dirname(self.python_exe), "pip-licenses.exe") if os.name == 'nt' else os.path.join(os.path.dirname(self.python_exe), "pip-licenses")
        
        cmd = [pip_licenses_exe, "--format=json", "--with-urls"]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        try:
            return {p['Name'].lower(): p for p in json.loads(result.stdout)}
        except json.JSONDecodeError:
            print(f"[ERROR] Error parsing pip-licenses output:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
            return {}

    def get_vulnerabilities(self):
        self.log("Scanning for vulnerabilities (pip-audit)...")
        # pip-audit returns non-zero exit code on vulns, so we don't check=True
        cmd = [self.python_exe, "-m", "pip_audit", "-f", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        self.audit_db_ok = True  # connectivity was already verified in pre-flight
        stderr_text = (result.stderr or "").strip()

        try:
            data = json.loads(result.stdout)
            deps = []
            if isinstance(data, dict) and 'dependencies' in data:
                deps = data['dependencies']
            elif isinstance(data, list):
                deps = data
            return deps
        except json.JSONDecodeError:
            self.audit_db_ok = False
            stdout_text = (result.stdout or "").strip()
            self.log("WARNING: pip-audit returned invalid JSON — audit results are unreliable.")
            self.log(f"  exit code: {result.returncode}")
            if stdout_text:
                self.log(f"  stdout: {stdout_text[:500]}")
            if stderr_text:
                self.log(f"  stderr: {stderr_text[:500]}")
            return []

    def fetch_pypi_metadata(self, name, version):
        url = PYPI_JSON_URL.format(name=name, version=version)
        try:
            with urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read())
                urls = data.get("urls", [])
                if not urls:
                    return None, None
                
                # Get latest upload time for this version
                last_upload = max(u["upload_time"] for u in urls)
                download_url = f"https://pypi.org/simple/{name}/"
                return last_upload, download_url
        except Exception:
            return None, None

    def collect_dependencies(self, tree):
        """
        Walks the (pre-filtered) dependency tree returned by pipdeptree -p <target>
        and collects every package name found. Returns a set of normalized names.
        """
        if not tree:
            self.log("Warning: Empty dependency tree from pipdeptree. Falling back to full scan.")
            return None

        relevant_packages = set()

        def walk(nodes):
            for node in nodes:
                # pipdeptree --json-tree puts key/package_name directly on the node
                key = node.get("key") or node.get("package_name") or ""
                normalized = self._normalize(key)
                if normalized:
                    relevant_packages.add(normalized)
                walk(node.get("dependencies", []))

        walk(tree)

        # Always include the target itself
        target_normalized = self._normalize(
            self.target_package.split('[')[0].split('=')[0].split('<')[0].split('>')[0]
        )
        relevant_packages.add(target_normalized)

        return relevant_packages

    def classify_dependencies(self, tree, install_report):
        """
        Returns:
          - relevant_keys: packages to include in audit scope
          - direct_keys: direct dependencies of target package
          - target_normalized: normalized target package name
        Priority:
          1) Scope from pip --report (complete resolver view)
          2) Fallback scope from pipdeptree tree
        Direct dependency detection uses pipdeptree top-level children when available.
        """
        target_normalized = self._normalize(
            self.target_package.split('[')[0].split('=')[0].split('<')[0].split('>')[0]
        )

        direct_keys = set()
        if tree and isinstance(tree, list):
            target_node = None
            for node in tree:
                node_key = self._normalize(node.get("key") or node.get("package_name") or "")
                if node_key == target_normalized:
                    target_node = node
                    break
            if target_node is None and tree:
                target_node = tree[0]

            for dep in (target_node or {}).get("dependencies", []):
                dep_key = self._normalize(dep.get("key") or dep.get("package_name") or "")
                if dep_key:
                    direct_keys.add(dep_key)

        report_keys = set()
        for entry in install_report or []:
            name = ((entry or {}).get("metadata") or {}).get("name", "")
            norm = self._normalize(name)
            if norm:
                report_keys.add(norm)

        if report_keys:
            relevant_keys = report_keys
            relevant_keys.add(target_normalized)
            return relevant_keys, direct_keys, target_normalized

        tree_keys = self.collect_dependencies(tree)
        if tree_keys is None:
            return None, direct_keys, target_normalized

        tree_keys.add(target_normalized)
        return tree_keys, direct_keys, target_normalized

    def audit(self):
        # 0. Pre-flight: verify we can reach vulnerability databases
        self.check_audit_connectivity()

        self.setup_environment()
        
        # 1. Get Base Data
        tree = self.get_dependency_tree()
        install_report = self.get_install_report()
        licenses = self.get_licenses()
        vulns_raw = self.get_vulnerabilities()

        # Map vulns by package name
        vulns_map = {}
        for v in vulns_raw:
            name = self._normalize(v.get("name", ""))
            if "vulns" in v and v["vulns"]:
                vulns_map[name] = [x["id"] for x in v["vulns"]]

        install_index = {}
        for entry in install_report or []:
            meta = (entry or {}).get("metadata") or {}
            pkg_name = meta.get("name", "")
            pkg_key = self._normalize(pkg_name)
            if not pkg_key:
                continue
            install_index[pkg_key] = {
                "name": pkg_name or pkg_key,
                "version": meta.get("version", "N/A"),
                "license": meta.get("license") or meta.get("license_expression") or "UNKNOWN"
            }

        # 2. Identify relevant packages (Target + Deps)
        relevant_keys, direct_keys, target_key = self.classify_dependencies(tree, install_report)

        # 3. Flatten and Enrich
        self.log("Enriching with PyPI data (updates, download links)...")
        
        # Pre-normalize tool package names for fallback comparison
        tool_keys = {self._normalize(t) for t in TOOL_PACKAGES}
        processed_keys = set()

        for pkg_name_raw, license_info in licenses.items():
            pkg_key = self._normalize(pkg_name_raw)
            
            # Filter: Must be in the target's dependency tree
            if relevant_keys is not None and pkg_key not in relevant_keys:
                continue
            
            # Fallback (tree unavailable): at least exclude audit tools
            if relevant_keys is None and pkg_key in tool_keys:
                continue

            version = license_info.get("Version")
            
            # Fetch remote info
            last_date, download_url = self.fetch_pypi_metadata(pkg_key, version)
            
            # Check Vulnerabilities
            pkg_vulns = vulns_map.get(pkg_key, [])
            if pkg_vulns:
                status = "VULNERABLE"
            elif not self.audit_db_ok:
                status = "AUDIT FAILED"
            else:
                status = "OK"
            
            # Check Risky Licenses
            lic_name = license_info.get("License", "UNKNOWN")
            is_risky = any(r in lic_name for r in RISKY_LICENSES)
            if is_risky:
                status = "RISKY LICENSE" if status == "OK" else status + ", RISKY LICENSE"

            if pkg_key == target_key:
                dependency_type = "ROOT"
            elif pkg_key in direct_keys:
                dependency_type = "DIRECT"
            else:
                dependency_type = "TRANSITIVE"

            self.results[pkg_key] = {
                "name": license_info.get("Name"),
                "version": version,
                "license": lic_name,
                "dependency_type": dependency_type,
                "status": status,
                "vulnerabilities": ", ".join(pkg_vulns),
                "last_updated": last_date or "N/A",
                "download_url": download_url or "N/A",
                "homepage": license_info.get("URL", "N/A")
            }
            processed_keys.add(pkg_key)
            # Rate limiting for PyPI
            time.sleep(0.1)

        if relevant_keys is not None:
            for pkg_key in sorted(relevant_keys):
                if pkg_key in processed_keys:
                    continue

                meta = install_index.get(pkg_key, {})
                pkg_name = meta.get("name", pkg_key)
                pkg_version = meta.get("version", "N/A")
                lic_name = meta.get("license", "UNKNOWN")

                if pkg_key == target_key:
                    dependency_type = "ROOT"
                elif pkg_key in direct_keys:
                    dependency_type = "DIRECT"
                else:
                    dependency_type = "TRANSITIVE"

                pkg_vulns = vulns_map.get(pkg_key, [])
                if pkg_vulns:
                    status = "VULNERABLE"
                elif not self.audit_db_ok:
                    status = "AUDIT FAILED"
                else:
                    status = "OK"

                if any(r in lic_name for r in RISKY_LICENSES):
                    status = "RISKY LICENSE" if status == "OK" else status + ", RISKY LICENSE"

                last_date, download_url = self.fetch_pypi_metadata(pkg_key, pkg_version)
                self.results[pkg_key] = {
                    "name": pkg_name,
                    "version": pkg_version,
                    "license": lic_name,
                    "dependency_type": dependency_type,
                    "status": status,
                    "vulnerabilities": ", ".join(pkg_vulns),
                    "last_updated": last_date or "N/A",
                    "download_url": download_url or "N/A",
                    "homepage": "N/A"
                }
                time.sleep(0.1)

    def generate_report(self):
        target_slug = self.target_package.split('[')[0].split('=')[0]
        csv_filename = f"audit_report_{target_slug}.csv"
        
        # Print Table
        print("\n" + "="*100)
        print(f" AUDIT REPORT: {self.target_package}")
        print("="*100)
        headers = ["Package", "Version", "Type", "License", "Updated", "Status", "Vulns"]
        row_fmt = "{:<20} {:<10} {:<11} {:<15} {:<12} {:<15} {:<20}"
        print(row_fmt.format(*headers))
        print("-" * 100)

        csv_rows = []
        csv_headers = [
            "Package", "Version", "Dependency Type",
            "License", "Status", "Vulnerabilities", "Last Updated", "Download URL", "Home Page"
        ]

        for pkg in sorted(self.results.values(), key=lambda x: x['name'].lower()):
            # Console Row
            ver_short = (pkg['version'][:10] + '..') if len(pkg['version']) > 10 else pkg['version']
            lic_short = (pkg['license'][:15] + '..') if len(pkg['license']) > 15 else pkg['license']
            vuln_short = (pkg['vulnerabilities'][:20] + '..') if len(pkg['vulnerabilities']) > 20 else pkg['vulnerabilities']
            
            print(row_fmt.format(
                pkg['name'], ver_short, pkg['dependency_type'],
                lic_short,
                pkg['last_updated'].split('T')[0] if pkg['last_updated'] != 'N/A' else 'N/A',
                pkg['status'],
                vuln_short
            ))

            # CSV Row
            csv_rows.append({
                "Package": pkg['name'],
                "Version": pkg['version'],
                "Dependency Type": pkg['dependency_type'],
                "License": pkg['license'],
                "Status": pkg['status'],
                "Vulnerabilities": pkg['vulnerabilities'],
                "Last Updated": pkg['last_updated'],
                "Download URL": pkg['download_url'],
                "Home Page": pkg['homepage']
            })

        # Write CSV
        def write_csv(path):
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=csv_headers)
                writer.writeheader()
                writer.writerows(csv_rows)

        try:
            write_csv(csv_filename)
            print("-" * 100)
            print(f"[OK] Detailed report saved to: {csv_filename}")
        except PermissionError:
            fallback_name = f"audit_report_{target_slug}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            try:
                write_csv(fallback_name)
                print("-" * 100)
                print(f"[WARN] Primary CSV is locked. Saved report to: {fallback_name}")
            except IOError as e:
                print(f"[ERROR] Could not write CSV (fallback failed): {e}")
        except IOError as e:
            print(f"[ERROR] Could not write CSV: {e}")

        # Cleanup
        try:
            import shutil
            shutil.rmtree(self.venv_dir, ignore_errors=True)
        except Exception:
            pass

if __name__ == "__main__":
    if sys.stdout.encoding.lower() != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except Exception:
            pass
            
    if len(sys.argv) < 2:
        print("Usage: python pylibs_check.py <package_name>")
        sys.exit(1)
    
    auditor = DependencyAuditor(sys.argv[1])
    auditor.audit()
    auditor.generate_report()