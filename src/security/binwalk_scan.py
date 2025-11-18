import json
import os
import sys
import struct
import math


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


def detect_steganographic_patterns(data):
    """Detecta patrones característicos de esteganografía ESPECÍFICAMENTE OpenStego"""
    anomalies = []
    steg_score = 0.0
    
    """
    OpenStego SIEMPRE:
    1. Incrusta datos DESPUÉS del marcador final
    2. Los datos típicamente son archivos comprimidos (ZIP/GZIP)
    3. Deja estructuras binarias reconocibles
    """
    
    # Firmas que buscar
    signatures = {
        b'\x50\x4b\x03\x04': ('ZIP local header', 0.45),
        b'\x50\x4b\x05\x06': ('ZIP central directory', 0.40),
        b'\x50\x4b\x07\x08': ('ZIP data descriptor', 0.40),
        b'\x1f\x8b\x08': ('GZIP detected', 0.42),
        b'\x42\x5a\x68': ('BZIP2 detected', 0.35),
        b'\x7z\xbc\xaf\x27\x1c': ('7-Zip detected', 0.35),
    }
    
    # Buscar en CUALQUIER LUGAR (OpenStego incrusta en cola)
    for sig, (name, score) in signatures.items():
        if sig in data:
            # Encontrar TODAS las instancias
            idx = 0
            found_count = 0
            while True:
                idx = data.find(sig, idx)
                if idx == -1:
                    break
                found_count += 1
                # Si está en segunda mitad del archivo = muy sospechoso
                if idx > len(data) * 0.5:
                    anomalies.append(f'{name} at offset {idx} (in tail data)')
                    steg_score += score
                idx += 1
            
            if found_count > 1:
                # Múltiples instancias = muy sospechoso
                anomalies.append(f'{name} found {found_count} times')
                steg_score += 0.25
    
    # Detectar patrones de bytes post-imagen típicos de OpenStego
    # OpenStego deja un patrón: datos comprimidos + metadatos
    tail_markers = [
        (b'\x50\x4b', 'ZIP'),  # ZIP
        (b'\x1f\x8b', 'GZIP'),  # GZIP
        (b'\x42\x5a', 'BZIP2'),  # BZIP2
    ]
    
    # Buscar estos marcadores específicamente en la segunda mitad
    mid_point = len(data) // 2
    tail_section = data[mid_point:]
    
    for marker, name in tail_markers:
        if marker in tail_section:
            anomalies.append(f'{name} archive in second half of file (tail data injection)')
            steg_score += 0.35
    
    # OpenStego típicamente introduce bytes NULL irregulares
    # pero solo es anómalo si está COMBINADO con otros indicadores
    null_count = data.count(b'\x00')
    if len(data) > 0:
        null_ratio = null_count / len(data)
        if null_ratio > 0.3:  # >30% es REALMENTE anómalo
            anomalies.append(f'Suspicious NULL byte ratio: {null_ratio:.2%}')
            steg_score += 0.25
    
    # Detectar entropía mixta: baja en imagen, alta en cola = esteganografía
    first_half_entropy = calculate_entropy(data[:len(data)//2])
    second_half_entropy = calculate_entropy(data[len(data)//2:])
    
    if second_half_entropy > 7.2 and first_half_entropy < 7.0:
        anomalies.append(f'Entropy jump: {first_half_entropy:.2f} -> {second_half_entropy:.2f} (steg pattern)')
        steg_score += 0.30
    
    return anomalies, min(steg_score, 1.0)


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
    """Detecta anomalías en la estructura del archivo - MENOS ESTRICTO"""
    anomalies = []
    
    # Verificar estructura de archivo esperada
    if filename.lower().endswith(('.jpg', '.jpeg')):
        if not data.startswith(b'\xff\xd8'):
            anomalies.append('JPEG header missing or invalid')
        if data[-2:] != b'\xff\xd9':
            anomalies.append('JPEG footer missing or corrupted')
    
    elif filename.lower().endswith('.png'):
        if not data.startswith(b'\x89PNG'):
            anomalies.append('PNG header missing or invalid')
        if len(data) < 8 or data[-8:] != b'\x00\x00\x00\x00IEND\xaeB`\x82':
            anomalies.append('PNG footer missing or corrupted')
    
    elif filename.lower().endswith('.gif'):
        if not data.startswith((b'GIF87a', b'GIF89a')):
            anomalies.append('GIF header missing or invalid')
        if not data.endswith(b'\x3b'):
            anomalies.append('GIF footer missing')
    
    # Solo marcar como anómalo si hay ratios REALMENTE altos
    entropy_ratio = analyze_entropy_chunks(data)
    if entropy_ratio > 0.8:  # Más de 80% de chunks con alta entropía
        anomalies.append(f'Very high entropy ratio: {entropy_ratio:.2%}')
    
    # Verificar distribución de entropía - más permisivo
    std_dev, high_ent_ratio = analyze_entropy_distribution(data)
    if std_dev > 3.5:  # Varianza muy alta
        anomalies.append(f'Abnormal entropy variance detected: {std_dev:.2f}')
    if high_ent_ratio > 0.7:  # Más de 70% de chunks
        anomalies.append(f'Too many high-entropy chunks: {high_ent_ratio:.2%}')
    
    return anomalies


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

    # Ejecutar análisis
    overall_entropy = calculate_entropy(data)
    binwalk_result = analyze_with_binwalk(target)
    tail_bytes = detect_trailing_bytes(data)
    structure_anomalies = detect_anomalies(data, target)
    steg_anomalies, steg_score = detect_steganographic_patterns(data)
    
    all_anomalies = structure_anomalies + steg_anomalies
    
    """
    CRITERIOS MÁXIMAMENTE AGRESIVOS - Rechazar CUALQUIER indicador de esteganografía:
    
    RECHAZAR SI:
    1. tail_bytes > 0 (CUALQUIER dato después del fin = sospechoso)
    2. steg_score > 0.30 (bajo umbral para detectar patrones)
    3. Binwalk encontró archivos comprimidos
    4. Estructura anómala
    
    PERMITIR SI:
    - EXACTAMENTE 0 bytes de tail
    - Estructura de imagen perfecta
    - Ningún indicador de compresión
    """
    
    # MEDIDA AGRESIVA 1: Cualquier tail data es sospechoso
    tail_suspicious = tail_bytes > 0  # Reducido de 200 a 0
    
    # MEDIDA AGRESIVA 2: Bajo umbral de steg_score
    steg_suspicious = steg_score > 0.25  # Reducido de 0.35 a 0.25
    
    # MEDIDA AGRESIVA 3: Cualquier hallazgo de binwalk es sospechoso
    binwalk_suspicious = len(binwalk_result.get('findings', [])) > 0
    
    # MEDIDA AGRESIVA 4: Cualquier anomalía de estructura
    structure_suspicious = len(structure_anomalies) > 0  # Reducido de >= 3 a > 0
    
    # Contar indicadores
    indicators = sum([
        tail_suspicious,
        steg_suspicious,
        binwalk_suspicious,
        structure_suspicious,
    ])
    
    # RECHAZAR SI EXISTE CUALQUIER INDICADOR
    suspicious = (
        tail_suspicious or        # Cualquier tail
        steg_suspicious or        # Bajo steg_score
        binwalk_suspicious or     # Cualquier hallazgo
        structure_suspicious      # Cualquier anomalía
    )

    build_response(
        supported=binwalk_result.get('supported', False),
        findings=binwalk_result.get('findings', []),
        anomalies=all_anomalies,
        suspicious=suspicious,
        tail_bytes=tail_bytes,
        steg_score=steg_score,
        entropy=overall_entropy,
        indicators_count=indicators,
    )


if __name__ == '__main__':
    main()
