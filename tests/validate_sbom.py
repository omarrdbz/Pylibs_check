"""Optional online conformance check: pip install jsonschema; pass SBOM paths."""
import json
import sys
from pathlib import Path
from urllib.request import urlopen

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource


def retrieve(uri):
    if not uri.startswith(('https://cyclonedx.org/schema/', 'http://cyclonedx.org/schema/')):
        raise ValueError(f'Unexpected schema reference: {uri}')
    # Read the versioned official repository; the website may reject automated clients.
    filename = uri.rsplit('/', 1)[-1]
    with urlopen('https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/' + filename, timeout=30) as response:
        return Resource.from_contents(json.load(response))


if __name__ == '__main__':
    schema = retrieve('https://cyclonedx.org/schema/bom-1.6.schema.json').contents
    validator = Draft7Validator(schema, registry=Registry(retrieve=retrieve), format_checker=FormatChecker())
    for filename in sys.argv[1:]:
        validator.validate(json.loads(Path(filename).read_text(encoding='utf-8')))
        print(f'CycloneDX 1.6 valid: {filename}')
