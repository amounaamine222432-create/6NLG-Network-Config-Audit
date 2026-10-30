"""Export parsing and normalized IR JSON for the first ten benchmark configs."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=HERE / 'export_10')
    args = parser.parse_args()
    sys.path[:0] = [str(args.project.resolve()), str((args.project / 'parsers').resolve())]
    from cisco_parser import parse_cisco_ios
    from normalizers.cisco_normalizer import normalize_cisco_ios

    parsing_dir = args.out / 'parsing'
    ir_dir = args.out / 'ir'
    parsing_dir.mkdir(parents=True, exist_ok=True)
    ir_dir.mkdir(parents=True, exist_ok=True)
    selected = sorted((HERE / 'configs').glob('*.cfg'))[:10]
    for config in selected:
        raw = config.read_bytes()
        parsed = parse_cisco_ios(raw.decode('utf-8-sig'))
        ir = normalize_cisco_ios(parsed, source_file=config.name,
                                 sha256=hashlib.sha256(raw).hexdigest())
        (parsing_dir / f'{config.stem}.parsing.json').write_text(
            json.dumps(parsed, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        (ir_dir / f'{config.stem}.ir.json').write_text(
            json.dumps(ir, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        print(config.name, 'interfaces=', len(parsed['interfaces']),
              'terminal_lines=', len(parsed['lines']))
    print('Exported', len(selected), 'parsing JSON and', len(selected), 'IR JSON')


if __name__ == '__main__':
    main()
