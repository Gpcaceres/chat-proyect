import json
import os
import sys


def build_response(**kwargs):
    payload = {
        'supported': False,
        'suspicious': False,
        'findings': [],
        'tail_bytes': 0,
    }
    payload.update(kwargs)
    sys.stdout.write(json.dumps(payload))


def analyze_with_binwalk(target):
    try:
        import binwalk  # type: ignore
    except Exception:  # pragma: no cover
        return {'supported': False, 'findings': [], 'suspicious': False, 'tail_bytes': 0}

    findings = []
    suspicious = False
    try:
        modules = binwalk.scan(target, signature=True, quiet=True)
        keywords = ('zip', 'rar', '7-zip', 'gzip', 'compressed', 'encrypted', 'archive')
        for module in modules:
            for result in getattr(module, 'results', []) or []:
                description = (result.description or '').lower()
                if any(keyword in description for keyword in keywords) and result.offset > 0:
                    suspicious = True
                    findings.append(
                        {
                            'offset': int(result.offset),
                            'description': result.description,
                        }
                    )
    except Exception:  # pragma: no cover
        return {'supported': False, 'findings': [], 'suspicious': False, 'tail_bytes': 0}

    return {
        'supported': True,
        'findings': findings,
        'suspicious': suspicious,
        'tail_bytes': 0,
    }


def detect_trailing_bytes(data):
    endings = [
        b"\x00\x00\x00\x00IEND\xaeB`\x82",  # PNG
        b"\xff\xd9",  # JPEG
        b"\x3b",  # GIF
    ]
    tail_bytes = 0
    for marker in endings:
        idx = data.rfind(marker)
        if idx != -1:
            end_pos = idx + len(marker)
            if len(data) > end_pos:
                tail_bytes = max(tail_bytes, len(data) - end_pos)
    return tail_bytes


def main():
    if len(sys.argv) < 2:
        build_response(error='missing_path')
        return

    target = sys.argv[1]
    if not os.path.exists(target):
        build_response(error='missing_file')
        return

    with open(target, 'rb') as handle:
        data = handle.read()

    binwalk_result = analyze_with_binwalk(target)
    tail_bytes = detect_trailing_bytes(data)
    suspicious = binwalk_result.get('suspicious', False) or tail_bytes > 512

    build_response(
        supported=binwalk_result.get('supported', False),
        findings=binwalk_result.get('findings', []),
        suspicious=suspicious,
        tail_bytes=tail_bytes,
    )


if __name__ == '__main__':
    main()
