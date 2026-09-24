"""Validate built wheel byte-for-byte and verify a copied bundle with networking disabled."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--python",required=True)
    parser.add_argument("--demo",required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    wheel=root/"dist"/"daconic_governance-0.2.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        for file in (root/"src"/"daconic_governance").glob("*.py"):
            assert archive.read("daconic_governance/"+file.name)==file.read_bytes(),file.name
    bundle=Path(args.demo)/"private-verification-bundle"
    with tempfile.TemporaryDirectory(prefix="daconic-offline-verification-") as temporary:
        destination=Path(temporary)/"bundle"
        shutil.copytree(bundle,destination)
        script="""
import socket,sys
def blocked(*a,**k): raise RuntimeError('Network disabled for offline verification')
class DisabledSocket(socket.socket):
    def __new__(cls,*a,**k): return blocked()
socket.socket=DisabledSocket
socket.create_connection=blocked
socket.getaddrinfo=blocked
from daconic_governance.cli import main
sys.exit(main())
"""
        reports=[]
        for flags,expected in [([],0),(["--no-blobs"],2)]:
            process=subprocess.run([args.python,"-c",script,"verify",str(destination),"--public-key",str(destination/"public.key"),*flags],
                                   cwd=temporary,capture_output=True,text=True)
            assert process.returncode==expected,(process.stdout,process.stderr)
            reports.append(json.loads(process.stdout))
        # Payload tamper must fail through the installed CLI, independently of the deployment.
        blob=next((destination/"blobs").iterdir())
        blob.write_bytes(b"tampered")
        process=subprocess.run([args.python,"-c",script,"verify",str(destination),"--public-key",str(destination/"public.key")],
                               cwd=temporary,capture_output=True,text=True)
        assert process.returncode==1,(process.stdout,process.stderr)
        reports.append(json.loads(process.stdout))
    report={"wheel_source_match":True,"wheel_sha256":hashlib.sha256(wheel.read_bytes()).hexdigest(),
            "offline_network_disabled":True,"verifier_runs":reports,"docker_runtime_tested":False,
            "cross_platform_tested":False}
    (root/"reports"/"release-checks.json").write_text(json.dumps(report,indent=2)+"\n")
    shutil.copyfile(Path(args.demo)/"demo-report.json",root/"reports"/"demo-report.json")
    shutil.copyfile(Path(args.demo)/"public-export.json",root/"reports"/"sample-public-export.json")
    from daconic_governance.api import SCHEMA
    (root/"docs"/"transaction.schema.json").write_text(json.dumps(SCHEMA,indent=2)+"\n")
    print(json.dumps(report,indent=2))


if __name__=="__main__": main()
