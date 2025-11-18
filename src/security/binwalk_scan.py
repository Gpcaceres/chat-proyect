import json
import os
import sys
from io import BytesIO

try:  # Pillow es opcional; si no existe, usamos heurísticas de bytes
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover - dependencia opcional
    Image = None


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


def analyze_lsb_distribution(data):
    """Analiza la distribución de bits menos significativos (LSB).

    Si Pillow está disponible, se realiza sobre los pixeles reales. De lo contrario,
    se evalúa una muestra de bytes del archivo para detectar distribuciones que
    parezcan demasiado uniformes (indicativo de esteganografía LSB).
    """

    def _lsb_suspicion(ones, total_bits, threshold=0.02):
        if total_bits == 0:
            return False
        ratio = ones / total_bits
        # Una distribución excesivamente uniforme alrededor de 0.5 puede indicar
        # inserción de datos cifrados en los megapíxeles de la imagen.
        return total_bits >= 5000 and abs(ratio - 0.5) < threshold

    if Image is not None:
        try:
            with Image.open(BytesIO(data)) as img:
                img = img.convert('RGB')
                width, height = img.size
                total_pixels = width * height
                if total_pixels == 0:
                    raise ValueError('invalid_image')
                sample_step = max(1, total_pixels // 400000)
                ones = 0
                total_bits = 0
                for index, (r, g, b) in enumerate(img.getdata()):
                    if index % sample_step != 0:
                        continue
                    ones += (r & 1) + (g & 1) + (b & 1)
                    total_bits += 3
                ratio = (ones / total_bits) if total_bits else 0
                return {
                    'supported': True,
                    'method': 'pillow',
                    'ratio': ratio,
                    'pixels_sampled': total_bits // 3,
                    'suspicious': _lsb_suspicion(ones, total_bits),
                    'width': width,
                    'height': height,
                }
        except Exception:
            # Caerá al análisis de bytes si Pillow falla o el archivo no es imagen
            pass

    ones = 0
    total_bits = 0
    sample_step = max(1, len(data) // 500000)
    for idx in range(0, len(data), sample_step):
        ones += data[idx] & 1
        total_bits += 1
    ratio = (ones / total_bits) if total_bits else 0
    return {
        'supported': bool(total_bits),
        'method': 'byte_stream',
        'ratio': ratio,
        'bytes_sampled': total_bits,
        'suspicious': _lsb_suspicion(ones, total_bits, threshold=0.015),
    }


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
    lsb_analysis = analyze_lsb_distribution(data)
    suspicious = (
        binwalk_result.get('suspicious', False)
        or tail_bytes > 512
        or lsb_analysis.get('suspicious', False)
    )

    build_response(
        supported=binwalk_result.get('supported', False),
        findings=binwalk_result.get('findings', []),
        suspicious=suspicious,
        tail_bytes=tail_bytes,
        lsb_analysis=lsb_analysis,
    )


if __name__ == '__main__':
    main()
