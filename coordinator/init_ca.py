#!/usr/bin/env python3
# federated/init_fl_ca.py
"""
One-time CLI: initialise the federation root CA + the coordinator's
server keypair.

Run ONCE on the FL coordinator host before starting the coordinator API.
The generated files are:

  ca_dir/ca_cert.pem            ← distribute to every org (out-of-band)
  ca_dir/ca_key.pem             ← KEEP SECRET, mode 600. Production: HSM/airgap.
  ca_dir/coordinator_cert.pem   ← consumed by uvicorn for TLS
  ca_dir/coordinator_key.pem    ← consumed by uvicorn for TLS
  ca_dir/crl.pem                ← empty CRL; regenerated on revocation

Usage:
  python -m coordinator.init_ca \\
      --ca-dir data/fl_coordinator/ca \\
      --hostname fl.example.com
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flproto.ca import init_ca


def main() -> int:
    ap = argparse.ArgumentParser(description="Initialise FL coordinator CA + server cert")
    ap.add_argument("--ca-dir", default="data/fl_coordinator/ca",
                    help="Where to write CA + coordinator material")
    ap.add_argument("--hostname", default="localhost",
                    help="Hostname the coordinator will be reachable at "
                         "(used for TLS server cert SAN)")
    ap.add_argument("--ca-validity-days", type=int, default=3650,
                    help="Root CA lifetime (default: 10 years)")
    ap.add_argument("--common-name", default="APT Platform Federation Root CA")
    args = ap.parse_args()

    try:
        result = init_ca(
            ca_dir=args.ca_dir,
            common_name=args.common_name,
            validity_days=args.ca_validity_days,
            coordinator_hostname=args.hostname,
        )
    except FileExistsError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        print("To rotate, archive the existing ca_dir and re-run.", file=sys.stderr)
        return 1

    print()
    print("═══════════════════════════════════════════════════════════════")
    print("  FEDERATION CA INITIALISED")
    print("═══════════════════════════════════════════════════════════════")
    print(f"  CA directory     : {result['ca_dir']}")
    print(f"  CA cert          : {result['ca_cert']}")
    print(f"  CA key (SECRET!) : {result['ca_key']}")
    print(f"  Coordinator cert : {result['coordinator_cert']}")
    print(f"  Coordinator key  : {result['coordinator_key']}")
    print(f"  CRL              : {result['crl']}")
    print()
    print("  NEXT STEPS:")
    print("    1. Distribute ca_cert.pem to every participating organisation")
    print("       (out-of-band — same channel as your enrollment trust process)")
    print("    2. Start the coordinator with TLS:")
    print(f"         FL_CA_DIR={result['ca_dir']} \\")
    print(f"         uvicorn coordinator.app:app \\")
    print(f"             --port 8889 \\")
    print(f"             --ssl-certfile {result['coordinator_cert']} \\")
    print(f"             --ssl-keyfile  {result['coordinator_key']} \\")
    print(f"             --ssl-ca-certs {result['ca_cert']} \\")
    print(f"             --ssl-cert-reqs 2")
    print("    3. Audit the CA key location — production: HSM or air-gapped host")
    print("═══════════════════════════════════════════════════════════════")
    return 0


if __name__ == "__main__":
    sys.exit(main())
