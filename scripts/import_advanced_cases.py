"""Import six chosen IOS CE configs from their original ZIP labs.

Only explicit member names are extracted; credentials files, YAML topologies,
and Cisco IOS XR P/PE configs are intentionally excluded.
"""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from zipfile import BadZipFile, ZipFile


# (archive, member inside archive, destination relative to output directory)
CASES = (
    ("ISP_BGP_Lab_Base.zip", "ISP_BGP_Lab_Base/CE-1.cfg", "isp_bgp_base/CE-1.cfg"),
    ("BGP_AS_PATH_Prepending.zip", "BGP_AS_PATH_Prepending/CE-1.cfg", "bgp_prepending/CE-1.cfg"),
    ("L3VPN-With-Route-Reflector.zip", "L3VPN With Route Reflector/CE1A.cfg", "l3vpn_rr/CE1A.cfg"),
    ("L2VPN_VPLS_configs.zip", "CE-1.cfg", "l2vpn_vpls/CE-1.cfg"),
    ("RSVP-TE_IOS_XRd.zip", "CE-1A.cfg", "rsvp_te_ce/CE-1A.cfg"),
    ("Segment_Routing.zip", "Segment_Routing/CE-1A.cfg", "segment_routing_ce/CE-1A.cfg"),
)


def main() -> int:
    cli = argparse.ArgumentParser(description="Import six selected Cisco IOS lab cases")
    cli.add_argument("zip_directory", type=Path, help="Directory containing original archive ZIPs")
    cli.add_argument("--output-dir", type=Path,
                     default=Path("data/advanced_cases"),
                     help="Default: data/advanced_cases (run from the project root)")
    args = cli.parse_args()

    # Validate every archive/member before writing anything.
    prepared = []
    for archive, member, relative in CASES:
        path = args.zip_directory / archive
        if not path.is_file():
            cli.error(f"Archive absente : {path}")
        try:
            with ZipFile(path) as z:
                payload = z.read(member)
        except (BadZipFile, KeyError) as exc:
            cli.error(f"Archive ou entrée invalide : {path}, {member}: {exc}")
        prepared.append((relative, payload))

    for relative, payload in prepared:
        target = args.output_dir / relative
        if target.exists() and target.read_bytes() != payload:
            cli.error(f"Le fichier existe avec un contenu différent, aucun écrasement : {target}")

    for relative, payload in prepared:
        target = args.output_dir / relative
        if target.exists():
            print(f"[EXISTANT] {target}")
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            print(f"[IMPORTÉ] {target} sha256={hashlib.sha256(payload).hexdigest()[:12]}")
        if re.search(rb"(?im)^\s*(?:username|enable secret|enable password|password|snmp-server community)\b", payload):
            print("  [PRUDENCE] Commandes pouvant contenir des identifiants : ne pas publier la configuration brute.")
    print("6 cas IOS importés ; aucun équipement IOS XR ni fichier credentials.txt.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
