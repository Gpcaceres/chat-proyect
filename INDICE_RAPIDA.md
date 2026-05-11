# 🔍 Índice de Referencia Rápida - ViroChat

**Última actualización**: 18 de noviembre de 2025

---

## 🔐 Buscar por Concepto de Seguridad

### Criptografía
- **AES-256-GCM** → `src/security/crypto.js` líneas 30-60
- **PBKDF2-SHA256** → `src/security/crypto.js` líneas 70-80
- **HMAC-SHA256** → `src/security/token.js` líneas 60-70
- **HMAC-SHA1** (TOTP) → `src/security/totp.js` líneas 20-45
- **Base64url** → `src/security/token.js` líneas 5-25

### Autenticación
- **JWT (signToken)** → `src/security/token.js` líneas 27-60
- **JWT (verifyToken)** → `src/security/token.js` líneas 63-95
- **TOTP (generateTotp)** → `src/security/totp.js` líneas 8-42
- **TOTP (verifyTotp)** → `src/security/totp.js` líneas 45-70
- **Login Admin** → `server.js` líneas 180-220
- **Login Sala** → `server.js` líneas 236-280

### Detección de Amenazas
- **Magic Numbers** → `src/security/fileType.js` líneas 5-30
- **Detección MIME** → `src/security/fileType.js` líneas 60-85
- **Análisis Entropía** → `src/security/stegWorker.js` líneas 35-50
- **Binwalk Scan** → `src/security/stegWorker.js` líneas 20-35
- **Trailing Bytes** → `src/security/binwalk_scan.py` líneas 35-50

### Rate Limiting
- **Token Bucket** → `src/security/rateLimiter.js` líneas 1-35
- **Cleanup** → `src/security/rateLimiter.js` líneas 20-30
- **Middleware** → `src/security/rateLimiter.js` líneas 33-60

---

## 🗄️ Buscar por Estructura de Datos

### Schemas MongoDB
- **Admin** → `src/models/Admin.js`
- **Room** → `src/models/Room.js`
- **AuditLog** → `src/models/AuditLog.js`
- **Attendance** → `src/models/Attendance.js`

### Estructuras de Sesión
- **sessionRegistry** → `server.js` líneas 95-110
- **deviceRegistry** → `server.js` líneas 110-115
- **sessionData** → `server.js` función `registerSession()` líneas 250-300

### Estructuras Criptográficas
- **Encrypted Data** → `{iv, content, authTag}`
- **Token Payload** → `{sub, exp, scope, ...metadata}`
- **TOTP Secret** → Base64 encoded 160-bit key

---

## 🔄 Buscar por Flujo

### Flujo: Login de Administrador
1. Usuario envía: usuario + contraseña + TOTP
2. Verificación: `src/security/crypto.js` `verifyHash()`
3. Validación 2FA: `src/security/totp.js` `verifyTotp()`
4. Generación JWT: `src/security/token.js` `signToken()`
5. Registro auditoría: `server.js` función `audit()`

**Archivos involucrados**: token.js, crypto.js, totp.js, AuditLog.js

---

### Flujo: Login a Sala
1. Usuario envía: roomId + PIN + nickname
2. Obtención sala: `Room.findOne()`
3. Verificación PIN: `src/security/crypto.js` `verifyHash()`
4. Validación dispositivo: `getFingerprint()`
5. Generación sessionId: `uuid()`
6. Creación sesión: `registerSession()`
7. Retorno clave cifrada: `decryptText()`

**Archivos involucrados**: Room.js, crypto.js, server.js

---

### Flujo: Carga de Archivo
1. Multer: Valida tipo MIME
2. File detection: `src/security/fileType.js` `detectFileType()`
3. Comparación tipos: Rechaza si no coinciden
4. Análisis esteganografía: `src/security/stegAnalyzer.js` `analyzeFile()`
5. Cálculo entropía: `stegWorker.js` `calculateEntropy()`
6. Binwalk scan: `binwalk_scan.py`
7. Rechazo si sospechoso
8. Almacenamiento si OK
9. Auditoría: `audit()`

**Archivos involucrados**: fileType.js, stegAnalyzer.js, stegWorker.js, binwalk_scan.py, AuditLog.js

---

## 📍 Buscar por Función

### Criptografía
| Función | Archivo | Línea | Tipo |
|---------|---------|-------|------|
| `getKey()` | crypto.js | 10 | Derivación |
| `encryptText()` | crypto.js | 20 | Cifrado |
| `decryptText()` | crypto.js | 40 | Descifrado |
| `hashSecret()` | crypto.js | 60 | Hash |
| `verifyHash()` | crypto.js | 75 | Verificación |
| `generateSessionKey()` | crypto.js | 95 | Sesión |

### Autenticación
| Función | Archivo | Línea | Tipo |
|---------|---------|-------|------|
| `base64UrlEncode()` | token.js | 5 | Codificación |
| `base64UrlDecode()` | token.js | 18 | Decodificación |
| `signToken()` | token.js | 32 | JWT Firma |
| `verifyToken()` | token.js | 63 | JWT Verificación |
| `generateTotp()` | totp.js | 8 | TOTP Generación |
| `verifyTotp()` | totp.js | 45 | TOTP Verificación |

### Detección de Archivos
| Función | Archivo | Línea | Tipo |
|---------|---------|-------|------|
| `bufferToHex()` | fileType.js | 40 | Conversión |
| `matchesSignature()` | fileType.js | 50 | Comparación |
| `looksLikeText()` | fileType.js | 60 | Heurística |
| `detectFileType()` | fileType.js | 75 | Detección |
| `analyzeFile()` | stegAnalyzer.js | 3 | Análisis |
| `calculateEntropy()` | stegWorker.js | 20 | Entropía |

### Seguridad del Servidor
| Función | Archivo | Línea | Tipo |
|---------|---------|-------|------|
| `rateLimiter()` | rateLimiter.js | 33 | Middleware |
| `cleanup()` | rateLimiter.js | 20 | Limpieza |
| `audit()` | server.js | 105 | Auditoría |
| `getFingerprint()` | server.js | 120 | Identificación |
| `sanitizeNickname()` | server.js | 130 | Sanitización |
| `ensureAdminAccount()` | server.js | 140 | Inicialización |

### Gestión de Sesiones
| Función | Archivo | Línea | Tipo |
|---------|---------|-------|------|
| `registerSession()` | server.js | 200 | Registro |
| `unregisterSession()` | server.js | 230 | Desregistro |
| `getRoomUsers()` | server.js | 250 | Listado |

---

## 🛡️ Buscar por Tipo de Amenaza

### Protección: Fuerza Bruta
- **Mecanismo**: PBKDF2 (120,000 iteraciones)
- **Archivo**: `src/security/crypto.js`
- **Función**: `hashSecret()`, `verifyHash()`
- **Tiempo/solicitud**: ~100ms
- **Rate limiter**: 100 req/60s

### Protección: MIME Sniffing
- **Mecanismo**: Magic numbers (firmas)
- **Archivo**: `src/security/fileType.js`
- **Función**: `detectFileType()`
- **Headers**: `X-Content-Type-Options: nosniff`

### Protección: Timing Attacks
- **Mecanismo**: `crypto.timingSafeEqual()`
- **Archivos**: `token.js`, `crypto.js`
- **Función**: `verifyHash()`, `verifyToken()`
- **Duración**: Constante independientemente de coincidencias

### Protección: Esteganografía
- **Mecanismo**: Análisis de entropía + binwalk
- **Archivo**: `src/security/stegWorker.js`, `binwalk_scan.py`
- **Umbral**: Entropía > 8.2 + bytes finales
- **Rechazo**: Archivo con hallazgos sospechosos

### Protección: Dispositivo Duplicado
- **Mecanismo**: Fingerprint (IP + User-Agent)
- **Archivo**: `server.js`
- **Función**: `getFingerprint()`, `registerSession()`
- **Prevención**: 1 dispositivo = 1 sala

### Protección: XSS
- **Mecanismo**: Headers HTTP
- **Header**: `X-XSS-Protection: 1; mode=block`
- **Recomendación**: Agregar CSP

### Protección: Clickjacking
- **Mecanismo**: Header HTTP
- **Header**: `X-Frame-Options: DENY`
- **Efecto**: No se puede incrustar en iframes

### Protección: Rate Limiting
- **Mecanismo**: Token Bucket por IP
- **Archivo**: `src/security/rateLimiter.js`
- **Límite**: 100 solicitudes/60 segundos
- **Código**: 429 (Too Many Requests)

---

## 📚 Buscar por Concepto

### JWT (JSON Web Tokens)
```
Estructura: header.payload.signature
Header: {"alg": "HS256", "typ": "JWT"}
Payload: {sub, exp, scope, ...datos}
Firma: HMAC-SHA256(header.payload)
Expiración: 3600 segundos (1 hora)
Ubicación: src/security/token.js
```

### TOTP (Time-based One-Time Password)
```
RFC: RFC 6238
HMAC: SHA-1
Período: 30 segundos
Código: 6 dígitos
Ventanas: -1, 0, +1 (±30s)
Ubicación: src/security/totp.js
```

### AES-256-GCM
```
Algoritmo: AES con Galois/Counter Mode
Clave: 256 bits (32 bytes)
IV: 12 bytes aleatorios
Tag: 128 bits (16 bytes)
Autenticidad: SÍ (autenticado)
Ubicación: src/security/crypto.js
```

### PBKDF2-SHA256
```
RFC: RFC 2898
Iteraciones: 120,000 (NIST 2023)
Función: SHA-256
Keylen: 32 bytes
Salt: 16 bytes aleatorios
Ubicación: src/security/crypto.js
```

### Magic Numbers (File Signatures)
```
PNG: 89 50 4E 47 0D 0A 1A 0A
JPEG: FF D8 FF E0/E1/E2/E3/E8
GIF: 47 49 46 38 37/39 61
PDF: 25 50 44 46
ZIP: 50 4B 03 04 / 05 06 / 07 08
BMP: 42 4D
Ubicación: src/security/fileType.js
```

---

## 🔗 Referencias Cruzadas

### Si lees `server.js`, también consulta:
- `src/security/crypto.js` - Para entender cifrado
- `src/security/token.js` - Para entender JWT
- `src/models/*.js` - Para entender esquemas
- `src/security/rateLimiter.js` - Para entender rate limiting

### Si lees `crypto.js`, también consulta:
- `src/security/token.js` - Usa funciones de crypto
- `src/models/Room.js` - Almacena datos cifrados
- `server.js` - Llama funciones de crypto

### Si lees `fileType.js`, también consulta:
- `src/security/stegAnalyzer.js` - Análisis posterior
- `src/security/stegWorker.js` - Cálculo de entropía
- `server.js` - Punto de entrada

---

## 💡 Tips de Búsqueda

### "¿Dónde se cifra...?"
- Datos en BD → `src/security/crypto.js` `encryptText()`
- Contraseña → `src/security/crypto.js` `hashSecret()`
- Mensaje usuario → `public/js/app.js` con Web Crypto API

### "¿Dónde se valida...?"
- Firma JWT → `src/security/token.js` `verifyToken()`
- Contraseña → `src/security/crypto.js` `verifyHash()`
- TOTP → `src/security/totp.js` `verifyTotp()`
- Tipo archivo → `src/security/fileType.js` `detectFileType()`

### "¿Dónde se registra...?"
- Acciones importantes → `server.js` `audit()`
- Datos auditoría → `src/models/AuditLog.js`

### "¿Dónde se limita...?"
- Solicitudes por IP → `src/security/rateLimiter.js`
- Tamaño archivo → `server.js` multer config (15 MB)
- Tipo archivo → `src/security/fileType.js` (MIME permitidos)

---

## 📖 Lectura Recomendada

### Para Principiantes:
1. `RESUMEN_COMENTARIOS.md` - Overview
2. `src/models/` - Entender estructuras
3. `src/security/fileType.js` - Concepto simple
4. `src/security/rateLimiter.js` - Algoritmo accesible

### Para Intermedios:
1. `src/security/crypto.js` - Criptografía
2. `src/security/token.js` - JWT
3. `server.js` - Flujo completo
4. `COMENTARIOS_CODIGO.md` - Documentación exhaustiva

### Para Avanzados:
1. `src/security/totp.js` - RFC 6238
2. `src/security/stegWorker.js` - Análisis entropía
3. `src/security/binwalk_scan.py` - Detección esteganografía
4. `public/js/app.js` - Cifrado E2E cliente

---

## 🎯 Casos de Uso Rápida

**"Necesito entender cómo se autentica un admin"**
→ Leer: `server.js` líneas 200-220, `src/security/crypto.js` y `token.js`

**"¿Qué protejas contra archivos maliciosos?"**
→ Leer: `src/security/fileType.js` y `stegAnalyzer.js`

**"¿Cómo se previene fuerza bruta?"**
→ Leer: `src/security/crypto.js` (PBKDF2) y `rateLimiter.js`

**"¿Cómo funciona el 2FA?"**
→ Leer: `src/security/totp.js` y `server.js` líneas 200-220

**"¿Cómo se cifra la comunicación?"**
→ Leer: `src/security/crypto.js` (servidor) y `public/js/app.js` (cliente)

