import argparse
import json
import os
import signal
from pathlib import Path

from .evidence import verify_bundle


def main():
    parser = argparse.ArgumentParser(prog="daconic")
    sub = parser.add_subparsers(dest="command",required=True)
    observe = sub.add_parser("observe-serve")
    observe.add_argument("--state", required=True)
    observe.add_argument("--policies", required=True)
    observe.add_argument("--host", default="127.0.0.1")
    observe.add_argument("--port", type=int, default=8080)
    observe.add_argument("--trusted-key")
    demo = sub.add_parser("demo"); demo.add_argument("--output",required=True)
    verify = sub.add_parser("verify"); verify.add_argument("bundle"); verify.add_argument("--public-key",required=True)
    verify.add_argument("--no-blobs",action="store_true")
    verify.add_argument("--replay-observations", action="store_true")
    bench = sub.add_parser("benchmark"); bench.add_argument("--output",required=True); bench.add_argument("--seconds",type=int,default=180); bench.add_argument("--rate",type=int,default=50)
    serve = sub.add_parser("serve"); serve.add_argument("--state",required=True); serve.add_argument("--policies"); serve.add_argument("--host",default="127.0.0.1"); serve.add_argument("--port",type=int,default=8080)
    serve.add_argument("--fixture",action="store_true"); serve.add_argument("--before"); serve.add_argument("--after")
    args = parser.parse_args()
    if args.command == "observe-serve":
        from .observation import Observer
        from .observation_api import make_observation_server
        token = os.environ.get("DACONIC_API_TOKEN", "")
        if len(token) < 32: parser.error("Set DACONIC_API_TOKEN to at least 32 random characters")
        files = sorted(Path(args.policies).glob("*.json"))
        if not files: parser.error("Observation policies required")
        key = Path(args.trusted_key).read_bytes() if args.trusted_key else None
        with Observer(args.state, [json.loads(p.read_text()) for p in files]) as app:
            server = make_observation_server(args.host, args.port, app, token, key)
            signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
            try: server.serve_forever()
            except KeyboardInterrupt: pass
            finally: server.server_close()
        return 0
    if args.command == "verify":
        directory = Path(args.bundle)
        data = json.loads((directory/"evidence.json").read_text())
        def reader(h):
            if not isinstance(h,str) or len(h)!=64 or any(c not in "0123456789abcdef" for c in h):
                raise ValueError("Invalid blob hash")
            p = directory/"blobs"/h
            return p.read_bytes() if p.exists() else None
        if args.replay_observations:
            if args.no_blobs: parser.error("Observation replay requires private blobs")
            from .observation import replay_observation_bundle
            report = replay_observation_bundle(data, Path(args.public_key).read_bytes(), reader)
            print(json.dumps(report, indent=2))
            return 1 if report["integrity"]["status"] == "FAIL" or report["replay"] == "FAIL" else 0 if report["replay"] == "PASS" else 2
        report = verify_bundle(data,Path(args.public_key).read_bytes(),None if args.no_blobs else reader)
        print(json.dumps(report,indent=2))
        return 0 if report["status"] == "PASS" else 2 if report["status"] == "INCOMPLETE" else 1
    if args.command == "demo":
        from .demo import run_demo
        print(json.dumps(run_demo(args.output),indent=2))
        return 0
    if args.command == "benchmark":
        from .benchmark import benchmark
        report = benchmark(args.output,args.seconds,args.rate)
        print(json.dumps({k:v for k,v in report.items() if k!="queue_samples"},indent=2))
        return 0 if report["verification"]["status"]=="PASS" and report["completed"]==report["offered_transactions"] else 1
    if args.command == "serve":
        from .application import Governance
        from .api import make_server
        from .fixtures import ExtractAdapter,FixtureAdapter,profile
        if args.fixture == bool(args.before and args.after):
            parser.error("Choose --fixture OR --before FILE --after FILE")
        credential = os.environ.get("DACONIC_API_TOKEN","")
        if len(credential)<32:
            parser.error("Set DACONIC_API_TOKEN to a random secret with at least 32 characters")
        adapter = FixtureAdapter() if args.fixture else ExtractAdapter(args.before,args.after)
        with Governance(args.state,adapter,args.policies) as app:
            if args.fixture and not args.policies:
                app.policies.install(profile()); app.policies.install(profile("reader-agent",True))
            if not app.policies.all(): parser.error("At least one policy is required")
            app.workers.start()
            server = make_server(args.host,args.port,app.queue,app.router,credential)
            def stop(*_): raise KeyboardInterrupt
            signal.signal(signal.SIGTERM,stop)
            try: server.serve_forever()
            except KeyboardInterrupt: pass
            finally: server.server_close()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
