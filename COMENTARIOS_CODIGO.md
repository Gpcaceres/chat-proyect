# Documentación de Comentarios - ViroChat

## 📄 Resumen de Archivos Comentados

Este documento proporciona una descripción detallada de todos los fragmentos de código en el proyecto ViroChat con explicaciones en español.

---

## 1️⃣ `server.js` - Servidor Principal Express + Socket.IO

### **Sección: IMPORTACIONES**
```javascript
// Módulos estándar: path (rutas), fs (sistema de archivos), http (servidor), crypto (criptografía)
// Express: framework web, Mongoose: ODM MongoDB, multer: carga de archivos
// Socket.IO: comunicación real-time bidireccional
```

### **Sección: CONFIGURACIÓN GENERAL**
```javascript
const PORT = 3000; // Puerto HTTP
const MONGODB_URI = "..."; // Conexión a base de datos
const TOKEN_SECRET = "..."; // Secreto para firmar JWT
const CRYPTO_SECRET = "..."; // Secreto para AES-256-GCM
const AUDIT_SECRET = "..."; // Secreto para HMAC auditoría
```

### **Función: `getFingerprint(req)`**
Genera una huella digital única del dispositivo:
- Combina dirección IP + User-Agent del navegador
- Calcula hash SHA256
- Se usa para detectar múltiples conexiones del mismo dispositivo

### **Función: `sanitizeNickname(nickname)`**
Limpia nombres de usuario:
- Remueve espacios al inicio/final
- Reduce espacios múltiples a uno
- Previene inyecciones de espacios

### **Función: `ensureAdminAccount()`**
Garantiza que existe admin en BD:
- Si existe: actualiza credenciales
- Si no existe: crea nuevo admin
- Hashea contraseña con PBKDF2 (120,000 iteraciones)
- Registra acción en auditoría

### **Función: `audit(action, actor, metadata)`**
Registra eventos importantes:
- Crea payload JSON con: acción, actor, metadata, timestamp
- Firma con HMAC-SHA256 para integridad
- Almacena en colección AuditLog

### **Middleware de Seguridad**
```javascript
// X-Content-Type-Options: nosniff → Previene MIME sniffing
// X-Frame-Options: DENY → Previene clickjacking
// X-XSS-Protection → Activa filtro XSS del navegador
// Referrer-Policy: no-referrer → Privacidad
```

### **Configuración de Multer**
- **Storage**: Almacena en `uploads/` con nombres únicos
- **Límite**: Máximo 15 MB por archivo
- **Filter**: Solo tipos MIME permitidos

### **Registros de Sesión**
```javascript
sessionRegistry = Map<roomId, Map<sessionId, sessionData>>
// Rastrea sesiones activas por sala
deviceRegistry = Map<fingerprint, roomId>
// Previene que dispositivo esté en dos salas simultáneamente
```

---

## 2️⃣ `src/security/crypto.js` - Criptografía AES-256-GCM

### **Constantes**
```javascript
ALGORITHM = 'aes-256-gcm' // Algoritmo de cifrado autenticado
PBKDF2_ITERATIONS = 120000 // Iteraciones de hashing (seguridad contra fuerza bruta)
KEYLEN = 32 // 256 bits para AES-256
```

### **Función: `getKey(secret)`**
- Toma secreto configurado
- Calcula hash SHA256
- Devuelve clave de 32 bytes

### **Función: `encryptText(plainText, secret)`**
Cifrado AES-256-GCM:
1. Genera IV aleatorio de 12 bytes
2. Cifra texto con AES-256-GCM
3. Obtiene tag de autenticación
4. Retorna: {iv, content, authTag} en base64

### **Función: `decryptText(encrypted, secret)`**
Descifrado AES-256-GCM:
1. Recibe {iv, content, authTag} en base64
2. Convierte de base64 a bytes
3. Valida tag de autenticación
4. Descifra texto

### **Función: `hashSecret(secret, salt, iterations)`**
Hash PBKDF2-SHA256:
- Genera salt aleatorio si no se proporciona
- 120,000 iteraciones contra ataques de fuerza bruta
- Retorna: {hash, salt, iterations}

### **Función: `verifyHash(secret, storedHash, salt, iterations)`**
Verificación segura:
- Usa `crypto.timingSafeEqual` para evitar timing attacks
- Compara hashes de forma constante en tiempo

### **Función: `generateSessionKey(secret)`**
Genera clave de sesión:
- Crea 32 bytes aleatorios
- Los cifra con AES-256-GCM
- Retorna clave cifrada

---

## 3️⃣ `src/security/token.js` - JWT Manual

### **Función: `base64UrlEncode(data)` / `base64UrlDecode(data)`**
Codificación base64url (RFC 7515):
- Reemplaza `+` → `-`, `/` → `_`
- Remueve padding `=`

### **Función: `signToken(payload, secret, expiresInSeconds)`**
Genera JWT:
1. Header: `{"alg": "HS256", "typ": "JWT"}`
2. Payload: incluye `exp` (timestamp de expiración)
3. Firma: HMAC-SHA256 de header.payload
4. Retorna: `header.payload.signature`

### **Función: `verifyToken(token, secret)`**
Valida JWT:
1. Verifica firma con `timingSafeEqual` (evita timing attacks)
2. Comprueba que token no esté expirado
3. Decodifica y retorna payload
4. Lanza error si es inválido

---

## 4️⃣ `src/security/totp.js` - Autenticación de Dos Factores

### **Función: `generateTotp(secret, window)`**
TOTP (RFC 6238):
1. Divide tiempo en pasos de 30 segundos
2. Crea buffer de 8 bytes con contador
3. HMAC-SHA1 del buffer
4. Extrae 6 últimos dígitos
5. `window`: para tolerancia de ±30 segundos

### **Función: `verifyTotp(token, secret)`**
Verifica código TOTP:
- Si no hay secreto: retorna `true` (2FA opcional)
- Valida código actual y ±1 ventana
- Retorna `true` si coincide

---

## 5️⃣ `src/security/fileType.js` - Detección de Tipos MIME

### **MAGIC_NUMBERS**
Array de firmas conocidas:
```javascript
PNG: 89 50 4E 47 0D 0A 1A 0A
JPEG: FF D8 FF E0/E1/E2/E3/E8
GIF: 47 49 46 38 37/39 61
PDF: 25 50 44 46
ZIP: 50 4B 03 04 / 05 06 / 07 08
```

### **Función: `matchesSignature(buffer, signature)`**
- Convierte bytes a hexadecimal
- Compara con firma esperada
- Permite identificar tipo real de archivo

### **Función: `looksLikeText(buffer)`**
Heurística para archivos de texto:
- Verifica que >90% de bytes sean imprimibles
- Rechaza bytes nulos

### **Función: `detectFileType(filePath)`**
Identificación de tipo:
1. Lee primeros bytes del archivo
2. Compara con firmas conocidas
3. Si no coincide, verifica si es texto
4. Retorna: {mime, ext} o null

---

## 6️⃣ `src/security/stegAnalyzer.js` - Análisis de Esteganografía

### **Función: `analyzeFile(filePath)`**
Wrapper que ejecuta análisis en Worker Thread:
1. Crea worker thread separado
2. Timeout de 10 segundos
3. Retorna resultado o rechaza
4. Termina worker después de análisis

---

## 7️⃣ `src/security/stegWorker.js` - Worker de Análisis

### **Función: `calculateEntropy(buffer)`**
Entropía de Shannon:
- Cuenta frecuencia de cada byte (0-255)
- Calcula `-Σ(p * log₂(p))` para cada probabilidad
- Rango: 0-8 bits
- **Indicador**: >7.5-8 = datos aleatorios (comprimidos/cifrados/esteganografiados)

### **Análisis de Binwalk**
Si entropía alta + bytes finales: marca como sospechoso
- Detecta archivos comprimidos/cifrados en extremo del archivo
- Indica posible esteganografía

---

## 8️⃣ `src/security/binwalk_scan.py` - Script Python

### **Función: `analyze_with_binwalk(target)`**
Ejecuta escaneo con binwalk:
- Busca firmas de archivos dentro del archivo
- Detecta ZIP, RAR, GZIP dentro de imágenes, etc.

### **Función: `detect_trailing_bytes(data)`**
Detecta bytes finales no estándar:
- Busca marcadores finales (PNG IEND, JPEG EOI, GIF trailer)
- Calcula bytes sobrantes
- >512 bytes = sospechoso

---

## 9️⃣ `src/security/rateLimiter.js` - Limitador de Velocidad

### **Configuración**
```javascript
WINDOW_MS = 60000 // Ventana de 60 segundos
MAX_REQUESTS = 100 // Máximo 100 solicitudes por ventana
```

### **Algoritmo: Token Bucket**
- Crea bucket por IP del cliente
- Incrementa contador cada solicitud
- Si >MAX_REQUESTS: rechaza con 429 (Too Many Requests)
- Limpia buckets expirados cada 60 segundos

---

## 🔟 `src/models/Admin.js` - Modelo Mongoose

```javascript
{
  username: String (único, requerido),
  passwordHash: String, // Resultado de PBKDF2
  passwordSalt: String, // Salt aleatorio
  passwordIterations: Number, // 120000
  totpSecret: String, // Base64 del secreto 2FA
  roles: [String], // Solo ['admin']
  lastLoginAt: Date,
  timestamps: { createdAt, updatedAt }
}
```

---

## 1️⃣1️⃣ `src/models/Room.js` - Modelo de Salas

```javascript
{
  roomId: String (UUID único),
  encryptedId: { iv, content, authTag }, // ID cifrado
  pinHash: String, // PBKDF2 del PIN
  pinSalt: String,
  pinIterations: Number,
  type: 'text' | 'multimedia',
  maxFileSizeMB: Number,
  createdBy: ObjectId (Admin),
  active: Boolean,
  sessionKey: { iv, content, authTag }, // Clave de sesión cifrada
  timestamps: { createdAt, updatedAt }
}
```

---

## 1️⃣2️⃣ `src/models/AuditLog.js` - Auditoría

```javascript
{
  action: String, // Tipo de evento
  actor: String, // Usuario que hizo la acción
  metadata: Mixed, // Datos contextuales
  signature: String, // HMAC-SHA256 para integridad
  timestamps: { createdAt }
}
```

---

## 1️⃣3️⃣ `public/js/app.js` - Frontend (Extracto)

### **Sección: Elementos DOM**
```javascript
// Elementos de pantalla: landing, chat, modales
// Entrada de usuario: room-id, pin, nickname
// Contenedores: messages, online-users, file-list
```

### **Función: `initializeSession(payload)`**
Configura sesión después de login:
1. Almacena token, info usuario, sala
2. Importa clave de sesión (AES-GCM)
3. Inicializa Socket.IO
4. Actualiza UI

### **Función: `encryptMessage(plainText)` / `decryptMessage(payload)`**
Cifrado E2E en navegador:
- Genera IV aleatorio de 12 bytes
- Usa Web Crypto API (AES-GCM nativo)
- Intercambia {iv, content} en base64

### **Función: `registerSession(roomId, nickname, fingerprint)`**
En servidor:
- Verifica que nickname no esté en uso
- Verifica que dispositivo no esté en otra sala
- Crea sessionId único
- Retorna sessionId

### **Función: `getRoomUsers(roomId)`**
Obtiene lista de usuarios conectados a una sala

---

## 1️⃣4️⃣ `public/css/styles.css` - Estilos

### **Variables CSS (Tema)**
```css
--bg-dark: #05030b /* Fondo principal */
--accent: #c71f36 /* Rojo neón */
--neon: #00f5ff /* Cyan neón */
--glass: rgba(17,13,34,0.75) /* Glassmorphism */
```

### **Componentes Principales**
- **Landing**: Pantalla de bienvenida con efectos blur
- **Modal**: Diálogos de login/admin
- **Chat**: Área principal con sidebar
- **Messages**: Contenedor de mensajes con templates
- **FilePreview**: Vistas previas de archivos (imágenes, metadata)
- **Toast**: Notificaciones emergentes

---

## 📊 Flujos de Seguridad

### **Login Admin**
1. Usuario envía usuario + contraseña + token TOTP
2. Servidor busca admin en BD
3. Verifica contraseña con `verifyHash()` (PBKDF2 timing-safe)
4. Verifica TOTP (±1 ventana)
5. Genera JWT firmado con 1 hora de expiración
6. Retorna token

### **Login Sala**
1. Usuario envía roomId + PIN + nickname
2. Servidor verifica PIN con `verifyHash()`
3. Valida nickname (no duplicado, ≥3 caracteres)
4. Verifica dispositivo (fingerprint)
5. Genera sessionId único
6. Cifra clave de sesión del cliente
7. Retorna sessionToken + sessionKey

### **Envío de Archivo**
1. Frontend: `authenticateUser` middleware valida token
2. Multer filtra por mimetype
3. Servidor: `detectFileType()` verifica firma real
4. Si mimetype ≠ firma: rechaza
5. `analyzeFile()` detecta esteganografía
6. Si entropía > 8.2 + bytes finales: rechaza
7. Almacena y emite vía Socket.IO

---

## 🔒 Mecanismos de Protección

| Amenaza | Protección |
|---------|-----------|
| Fuerza bruta | PBKDF2 (120k iteraciones), rate limiter (100 req/60s) |
| CSRF | Token JWT único por sesión |
| XSS | Headers X-XSS-Protection, CSP implícito |
| Timing attacks | `crypto.timingSafeEqual()` |
| Clickjacking | X-Frame-Options: DENY |
| MIME sniffing | X-Content-Type-Options: nosniff |
| Man-in-the-Middle | HTTPS recomendado, JWT firmado |
| Dispositivo duplicado | Fingerprint (IP + User-Agent) |
| Esteganografía | Análisis entropía + binwalk |
| Múltiples conexiones | SessionRegistry + deviceRegistry |

---

## 🚀 Arquitectura General

```
┌─────────────────────────────────────────────────────────┐
│                   FRONTEND (Browser)                    │
│  ├─ app.js: Lógica cliente, Web Crypto API (AES-GCM)  │
│  └─ index.html: UI con templates                       │
└────────────────────────┬────────────────────────────────┘
                         │ HTTP/WebSocket
┌────────────────────────▼────────────────────────────────┐
│              EXPRESS SERVER (Node.js)                   │
│  ├─ server.js: Rutas, middleware, Socket.IO            │
│  ├─ Seguridad: crypto.js, token.js, totp.js            │
│  ├─ Upload: multer + file detection + steg analysis    │
│  └─ Modelos: Admin, Room, AuditLog                      │
└────────────────────────┬────────────────────────────────┘
                         │ TCP
┌────────────────────────▼────────────────────────────────┐
│                   MONGODB                               │
│  ├─ Admins (usuarios administradores)                  │
│  ├─ Rooms (salas de chat)                              │
│  └─ AuditLogs (registro de eventos)                    │
└─────────────────────────────────────────────────────────┘
```

---

## 📝 Notas Importantes

1. **Token JWT**: Expiración 1 hora
2. **Entropía umbral**: >8.2 se considera sospechosa
3. **Rate Limiter**: Global por IP (100 solicitudes/minuto)
4. **Fingerprint**: Previene múltiples conexiones simultáneas
5. **Cifrado E2E**: AES-256-GCM en navegador
6. **Auditoría**: Toda acción se registra con firma HMAC

---

**Última actualización**: 18 de noviembre de 2025
**Proyecto**: ViroChat - Chat Seguro con Análisis de Seguridad
