import json
import math
import os
import shutil
import struct
import subprocess
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
        'anomalies': [],
        'steg_score': 0.0,
    }
    payload.update(kwargs)
    sys.stdout.write(json.dumps(payload))


def calculate_entropy(data):
    """Calcula entropía Shannon"""
    if len(data) == 0:
        return 0
    
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    entropy = 0.0
    for count in byte_counts.values():
        p = count / len(data)
        entropy -= p * (p and math.log2(p) or 0)
    
    return entropy


def detect_chi_square_anomaly(data):
    """Detecta anomalías usando test chi-cuadrado de distribución de bytes"""
    if len(data) < 256:
        return 0.0
    
    # Contar frecuencia de cada byte
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    # Frecuencia esperada si estuviera uniformemente distribuido
    expected = len(data) / 256.0
    
    # Calcular chi-cuadrado
    chi_square = 0.0
    for count in byte_counts:
        if expected > 0:
            chi_square += ((count - expected) ** 2) / expected
    
    # Normalizar a 0-1
    return min(chi_square / 1000.0, 1.0)


def analyze_entropy_distribution(data, chunk_size=256):
    """Analiza distribución de entropía en chunks"""
    entropies = []
    high_entropy_chunks = 0
    low_entropy_chunks = 0
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        entropy = calculate_entropy(chunk)
        entropies.append(entropy)
        if entropy > 7.6:
            high_entropy_chunks += 1
        elif entropy < 2.5:
            low_entropy_chunks += 1
    
    if len(entropies) == 0:
        return 0.0, 0.0
    
    # Calcular varianza de la entropía
    avg_entropy = sum(entropies) / len(entropies)
    variance = sum((e - avg_entropy) ** 2 for e in entropies) / len(entropies)
    std_dev = math.sqrt(variance) if variance >= 0 else 0
    
    high_entropy_ratio = high_entropy_chunks / len(entropies)
    
    return std_dev, high_entropy_ratio


# Known archive magic signatures for tail detection
_ARCHIVE_SIGNATURES = [
    (b'\x50\x4b\x03\x04', 'ZIP'),
    (b'\x50\x4b\x05\x06', 'ZIP (empty)'),
    (b'\x1f\x8b', 'GZIP'),
    (b'\x52\x61\x72\x21', 'RAR'),
    (b'\x37\x7a\xbc\xaf', '7Z'),
    (b'\x42\x5a\x68', 'BZIP2'),
]


def find_image_end_offset(data):
    """Returns the byte offset where the image legitimately ends (start of tail area).
    Returns -1 if no recognised image end marker is found."""
    best = -1

    # JPEG: last FF D9 (EOI marker)
    for i in range(len(data) - 1, 0, -1):
        if data[i - 1] == 0xFF and data[i] == 0xD9:
            best = max(best, i + 1)
            break

    # PNG: last IEND chunk + CRC (8 bytes total: "IEND" + 4-byte CRC 0xAE426082)
    # CRC of IEND is always constant, so this is unambiguous
    iend_full = b'IEND\xaeB`\x82'
    idx = data.rfind(iend_full)
    if idx != -1:
        best = max(best, idx + len(iend_full))

    # GIF: last trailer byte 0x3B (only within last 16 bytes to avoid false matches)
    for i in range(len(data) - 1, max(len(data) - 16, -1), -1):
        if data[i] == 0x3B:
            best = max(best, i + 1)
            break

    return best


def detect_archive_in_tail(data):
    """Detects archive magic bytes strictly AFTER the image end marker.
    This is the most reliable method: OpenStego always appends a ZIP/GZIP
    container after the image terminator. Searching the 'second half' of the
    file is NOT reliable because JPEG DCT data contains every byte sequence."""
    anomalies = []
    end_offset = find_image_end_offset(data)

    if end_offset <= 0 or end_offset >= len(data):
        return anomalies, 0.0  # No image end found or no tail data

    tail = data[end_offset:]
    # Strip null-byte camera/encoder padding (Canon, Nikon often add a few null bytes)
    stripped = tail.lstrip(b'\x00')
    if not stripped:
        return anomalies, 0.0  # Only null padding — natural, not suspicious

    for sig, name in _ARCHIVE_SIGNATURES:
        if stripped[:len(sig)] == sig or sig in stripped[:2048]:
            anomalies.append(f'{name} archive signature in tail at offset {end_offset}')
            return anomalies, 0.90  # High confidence: hidden payload appended after image

    # Tail exists but no archive signature — score by size and entropy
    tail_entropy = calculate_entropy(stripped[:4096])
    if len(stripped) > 512 and tail_entropy > 7.5:
        anomalies.append(
            f'High-entropy tail: {len(stripped)} bytes, entropy={tail_entropy:.2f}'
        )
        return anomalies, 0.55  # Suggestive, but not definitive alone (< rejection threshold)

    return anomalies, 0.0  # Small or low-entropy tail — not suspicious


def analyze_entropy_chunks(data, chunk_size=512):
    """Analiza la entropía en chunks para detectar anomalías locales"""
    high_entropy_chunks = 0
    low_entropy_chunks = 0
    
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        entropy = calculate_entropy(chunk)
        if entropy > 7.5:
            high_entropy_chunks += 1
        elif entropy < 3.0:
            low_entropy_chunks += 1
    
    high_entropy_ratio = high_entropy_chunks / max(len(data) // chunk_size, 1)
    return high_entropy_ratio


def analyze_with_binwalk(target):
    try:
        import binwalk  # type: ignore
    except Exception:  # pragma: no cover
        return {'supported': False, 'findings': [], 'suspicious': False, 'tail_bytes': 0}

    findings = []
    suspicious = False
    try:
        modules = binwalk.scan(target, signature=True, quiet=True)
        # Solo marcar como sospechoso si encuentra archivos DENTRO de la imagen
        keywords = ('zip', 'rar', '7-zip', 'gzip', 'bzip2', 'xz', 'encrypted')
        for module in modules:
            for result in getattr(module, 'results', []) or []:
                description = (result.description or '').lower()
                # Solo si offset > 0 y es después del inicio (dentro del archivo)
                if any(keyword in description for keyword in keywords) and result.offset > 512:
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
    """Detecta bytes adicionales después de los marcadores finales"""
    endings = [
        b"\x00\x00\x00\x00IEND\xaeB`\x82",  # PNG
        b"\xff\xd9",  # JPEG
        b"\x3b",  # GIF
        b"%EOF",  # PDF
    ]
    tail_bytes = 0
    for marker in endings:
        idx = data.rfind(marker)
        if idx != -1:
            end_pos = idx + len(marker)
            if len(data) > end_pos:
                tail_bytes = max(tail_bytes, len(data) - end_pos)
    return tail_bytes


def detect_anomalies(data, filename):
    """Detecta anomalías estructurales en el archivo."""
    anomalies = []
    fname = os.path.basename(filename).lower()

    if fname.endswith(('.jpg', '.jpeg')):
        if not data[:2] == b'\xff\xd8':
            anomalies.append('JPEG header missing or invalid')
        if data[-2:] != b'\xff\xd9':
            anomalies.append('JPEG footer missing or corrupted')
    elif fname.endswith('.png'):
        if not data[:4] == b'\x89PNG':
            anomalies.append('PNG header missing or invalid')
        if len(data) < 8 or data[-8:] != b'\x00\x00\x00\x00IEND\xaeB`\x82':
            anomalies.append('PNG footer missing or corrupted')
    elif fname.endswith('.gif'):
        if not (data[:6] in (b'GIF87a', b'GIF89a')):
            anomalies.append('GIF header missing or invalid')
        if not data.endswith(b'\x3b'):
            anomalies.append('GIF footer missing')

    return anomalies


def probe_steghide(target):
    """Detecta datos ocultos usando steghide (sin contraseña). Devuelve resultado vacío si no está disponible."""
    steghide_path = shutil.which('steghide')
    if not steghide_path:
        return {'available': False, 'suspicious': False, 'status': 'missing'}

    try:
        result = subprocess.run(
            [steghide_path, 'info', target, '-p', ''],
            capture_output=True, text=True, check=False, timeout=15,
        )
    except Exception as exc:
        return {'available': True, 'suspicious': False, 'status': 'error', 'error': str(exc)}

    combined = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
    normalized = combined.lower()
    suspicious = False
    status = 'clean'

    if 'could not extract any data with that passphrase' in normalized:
        suspicious = True
        status = 'password_protected'
    elif 'embedded data' in normalized and result.returncode == 0:
        suspicious = True
        status = 'embedded_data'
    elif 'encryption algorithm' in normalized or 'passphrase' in normalized:
        suspicious = True
        status = 'possibly_encrypted'
    elif result.returncode != 0:
        status = 'error'

    return {
        'available': True,
        'suspicious': suspicious,
        'status': status,
        'output': combined[:500],
    }


def analyze_lsb_distribution(data):
    """Analiza distribución de LSB para detectar esteganografía LSB.
    Usa Pillow (análisis por píxel RGB) si está disponible; si no, muestrea bytes."""

    def _lsb_suspicious(ones, total, threshold=0.008):
        if total < 5000:
            return False
        return abs(ones / total - 0.5) < threshold

    if Image is not None:
        try:
            with Image.open(BytesIO(data)) as img:
                img = img.convert('RGB')
                width, height = img.size
                if width * height == 0:
                    raise ValueError('empty')
                step = max(1, (width * height) // 400000)
                ones = 0
                total = 0
                ch_ones = [0, 0, 0]
                ch_total = [0, 0, 0]
                for i, (r, g, b) in enumerate(img.getdata()):
                    if i % step != 0:
                        continue
                    for j, v in enumerate((r, g, b)):
                        bit = v & 1
                        ones += bit
                        ch_ones[j] += bit
                        total += 1
                        ch_total[j] += 1
                ratio = ones / total if total else 0
                channel_stats = []
                channel_alert = False
                for idx, label in enumerate('RGB'):
                    cr = ch_ones[idx] / ch_total[idx] if ch_total[idx] else 0
                    alert = ch_total[idx] >= 1500 and abs(cr - 0.5) < 0.008
                    channel_alert = channel_alert or alert
                    channel_stats.append({'channel': label, 'ratio': cr, 'suspicious': alert})
                # Require BOTH the overall ratio AND at least one channel to be anomalous
                # to avoid false positives on natural JPEG images (JPEG DCT naturally
                # produces pixel LSBs close to 0.5 for high-detail images)
                suspicious = _lsb_suspicious(ones, total) and channel_alert
                return {
                    'method': 'pillow_rgb',
                    'ratio': ratio,
                    'pixels_sampled': total,
                    'rgb_channels': channel_stats,
                    'suspicious': suspicious,
                    'score': 0.50 if suspicious else 0.0,
                }
        except Exception:
            pass  # fall through to byte sampling

    # Fallback: byte-level LSB sampling
    step = max(1, len(data) // 500000)
    ones = sum((data[i] & 1) for i in range(0, len(data), step))
    total = len(range(0, len(data), step))
    ratio = ones / total if total else 0
    suspicious = _lsb_suspicious(ones, total, threshold=0.008)
    return {
        'method': 'byte_stream',
        'ratio': ratio,
        'bytes_sampled': total,
        'suspicious': suspicious,
        'score': 0.50 if suspicious else 0.0,
    }


def _steghide_score(probe_result):
    """Converts probe_steghide result into a numeric confidence score."""
    if not probe_result or not probe_result.get('suspicious'):
        return 0.0
    status = probe_result.get('status', '')
    return 0.95 if status == 'embedded_data' else 0.85 if status == 'password_protected' else 0.75


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

    overall_entropy = calculate_entropy(data)
    binwalk_result = analyze_with_binwalk(target)
    tail_bytes = detect_trailing_bytes(data)
    structure_anomalies = detect_anomalies(data, target)
    # Use detect_archive_in_tail: only archive sigs AFTER image end are reliable signals
    tail_anomalies, tail_archive_score = detect_archive_in_tail(data)
    all_anomalies = structure_anomalies + tail_anomalies

    # Optional detectors (require extra dependencies)
    lsb_analysis = analyze_lsb_distribution(data)
    steghide_info = probe_steghide(target)

    # ── Weighted scoring ──────────────────────────────────────────────────────
    # Only use reliable signals to avoid false positives on normal images.
    # JPEG DCT data naturally contains every byte sequence, so scanning the
    # 'second half' of a file is NOT a valid steganography signal.

    lsb_score = 0.40 if lsb_analysis.get('suspicious') else 0.0
    steghide_score = _steghide_score(steghide_info)
    binwalk_score = 0.80 if binwalk_result.get('suspicious') else 0.0

    scores = {
        'tail_archive': tail_archive_score,  # archive bytes after image end (reliable)
        'steghide': steghide_score,          # steghide tool confirmation (reliable)
        'binwalk': binwalk_score,            # binwalk embedded archive (reliable)
        'lsb': lsb_score,                   # LSB anomaly (weak, needs support)
    }

    final_score = max(scores.values())

    # Boost only when 2+ strong independent signals agree (not LSB alone)
    strong_signals = sum(1 for k, v in scores.items() if v >= 0.65 and k != 'lsb')
    if strong_signals >= 2:
        final_score = min(final_score + 0.10, 1.0)
    elif lsb_score >= 0.40 and any(v >= 0.65 for k, v in scores.items() if k != 'lsb'):
        final_score = min(final_score + 0.05, 1.0)

    signals_firing = sum(1 for v in scores.values() if v >= 0.40)
    suspicious = final_score >= 0.65

    build_response(
        supported=binwalk_result.get('supported', False),
        findings=binwalk_result.get('findings', []),
        anomalies=all_anomalies,
        suspicious=suspicious,
        tail_bytes=tail_bytes,
        steg_score=final_score,
        entropy=overall_entropy,
        indicators_count=signals_firing,
        scores=scores,
        lsb_analysis=lsb_analysis,
        steghide_probe=steghide_info,
    )


if __name__ == '__main__':
    main()