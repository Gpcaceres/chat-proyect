# 🚀 ViroChat - Testing & Execution Guide

## 📋 Tabla de Contenidos
1. [Instalación](#instalación)
2. [Estructura del Proyecto](#estructura-del-proyecto)
3. [Ejecutar Pruebas](#ejecutar-pruebas)
4. [Ejecutar la Aplicación](#ejecutar-la-aplicación)
5. [Módulos de Seguridad](#módulos-de-seguridad)
6. [Documentación](#documentación)

---

## 📦 Instalación

### Prerequisitos
- Node.js v14+
- npm o yarn
- MongoDB (para base de datos)
- Docker (opcional)

### Pasos

```bash
# Clonar o abrir proyecto
cd chat-proyect

# Instalar dependencias
npm install

# Instalar dependencias de desarrollo (Jest, Supertest)
npm install --save-dev jest supertest @types/jest

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores
```

---

## 📂 Estructura del Proyecto

```
chat-proyect/
├── public/
│   ├── index.html
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── app.js
├── src/
│   ├── models/
│   │   ├── Admin.js          ✅ Comentado
│   │   ├── Attendance.js     ✅ Comentado (REPARADO)
│   │   ├── AuditLog.js       ✅ Comentado
│   │   └── Room.js           ✅ Comentado
│   └── security/
│       ├── crypto.js         ✅ Comentado + Probado (20 tests)
│       ├── token.js          ✅ Comentado + Probado (16 tests)
│       ├── totp.js           ✅ Comentado + Probado (15 tests)
│       ├── fileType.js       ✅ Comentado + Probado (18 tests)
│       ├── rateLimiter.js    ✅ Comentado
│       ├── stegAnalyzer.js   ✅ Comentado
│       ├── stegWorker.js     ✅ Comentado
│       ├── binwalk_scan.py   ✅ Comentado
│       └── token.js
├── tests/
│   ├── unit/
│   │   ├── crypto.test.js       ✅ 20 tests
│   │   ├── token.test.js        ✅ 16 tests
│   │   ├── totp.test.js         ✅ 15 tests
│   │   └── fileType.test.js     ✅ 18 tests
│   ├── integration/             📝 Estructura lista
│   └── security/
│       └── security.test.js     ✅ 13 tests (OWASP Top 10)
├── uploads/
│   └── [archivos subidos]
├── jest.config.js              ✅ Configurado
├── package.json                ✅ Scripts de test actualizados
├── server.js                   ✅ Comentado
├── Dockerfile
├── docker-compose.yml
├── COMENTARIOS_CODIGO.md       📖 Documentación completa
├── RESUMEN_COMENTARIOS.md      📖 Resumen ejecutivo
└── REPORTE_PRUEBAS.md          📊 Este archivo
```

---

## 🧪 Ejecutar Pruebas

### Opción 1: Todas las Pruebas
```bash
npm test
```
**Resultado esperado**: ✅ 82 tests passed in ~90s

### Opción 2: Por Categoría

#### Pruebas Unitarias
```bash
npm run test:unit
```
Incluye:
- Criptografía (crypto.test.js) - 20 tests
- JWT/Tokens (token.test.js) - 16 tests
- TOTP 2FA (totp.test.js) - 15 tests
- Detección MIME (fileType.test.js) - 18 tests

#### Pruebas de Seguridad (OWASP Top 10)
```bash
npm run test:security
```
Incluye:
- A1: Inyección (3 tests)
- A02: Fallo de Autenticación (3 tests)
- A03: Inyección de Datos (2 tests)
- A05: Control de Acceso (2 tests)
- A06: Información Sensible (3 tests)
- CVSS Simulados (2 tests)
- Esteganografía (2 tests)

#### Pruebas de Integración
```bash
npm run test:integration
```
*Nota: Estructura lista, implementación pendiente con Supertest*

### Opción 3: Con Cobertura
```bash
npm run test:coverage
```
Genera reporte de cobertura con umbral del 70%

**Salida esperada**:
```
Test Suites: 5 passed, 5 total
Tests:       82 passed, 82 total
Coverage:    >70% en módulos auditados
```

### Opción 4: Modo Watch (Desarrollo)
```bash
npm run test:watch
```
Reejecuta tests automáticamente al editar archivos

---

## 🚀 Ejecutar la Aplicación

### Opción 1: Desarrollo Local
```bash
npm start
```

**Espera ver**:
```
Server listening on port 3000
Database connected to MongoDB
Socket.IO initialized
```

Luego abre: http://localhost:3000

### Opción 2: Con Docker
```bash
# Construir imagen
docker build -t virochat .

# Ejecutar contenedor
docker run -p 3000:3000 virochat
```

### Opción 3: Docker Compose (Recomendado)
```bash
docker-compose up
```

Esto levanta:
- Node.js app en puerto 3000
- MongoDB en puerto 27017
- Volúmenes persistentes para datos

---

## 🔒 Módulos de Seguridad

### 1. Criptografía (`src/security/crypto.js`)
- **Cifrado**: AES-256-GCM
- **Hashing**: PBKDF2-SHA256 (120,000 iteraciones)
- **IV**: Aleatorio para cada cifrado
- **Auth Tag**: Validación de integridad
- **Pruebas**: ✅ 20 cases - Todas pasadas

```javascript
// Uso
const encrypted = encryptText('Mensaje secreto', secretKey);
const decrypted = decryptText(encrypted, secretKey);
```

### 2. JWT / Tokens (`src/security/token.js`)
- **Algoritmo**: HMAC-SHA256
- **Formato**: RFC 7519
- **Expiración**: 1 hora (configurable)
- **Payload protegido**: Detección de manipulación
- **Pruebas**: ✅ 16 cases - Todas pasadas

```javascript
// Uso
const token = signToken({ sub: 'user1', role: 'admin' }, secret);
const verified = verifyToken(token, secret);
```

### 3. TOTP 2FA (`src/security/totp.js`)
- **Estándar**: RFC 6238
- **Ventana de tiempo**: ±30 segundos
- **Autenticador**: Google Authenticator compatible
- **Pruebas**: ✅ 15 cases - Todas pasadas

```javascript
// Uso
const valid = verifyTotp(token, secret);
```

### 4. Detección MIME (`src/security/fileType.js`)
- **Magic Numbers**: Validación de firma
- **Soportados**: PNG, JPEG, PDF, ZIP, TXT
- **Heurística**: Fallback UTF-8
- **Pruebas**: ✅ 18 cases - Todas pasadas

```javascript
// Uso
const fileInfo = detectFileType('/path/to/file');
// { mime: 'image/png', ext: 'png' }
```

### 5. Rate Limiting (`src/security/rateLimiter.js`)
- **Algoritmo**: Token Bucket
- **Límite**: 100 solicitudes / 60 segundos por IP
- **Limpieza automática**: Cada 5 minutos

```javascript
// Uso (middleware)
app.use(rateLimitMiddleware);
```

### 6. Esteganografía (`src/security/stegAnalyzer.js`)
- **Análisis**: Entropía Shannon
- **Detección**: Patrones de datos ocultos
- **Worker**: Procesamiento en segundo plano

```javascript
// Uso
const analysis = analyzeSteganography(fileBuffer);
```

---

## 📖 Documentación

### Archivos Generados

#### 1. `COMENTARIOS_CODIGO.md`
Documentación completa con:
- Arquitectura del proyecto
- Explicación de cada módulo
- Fragmentos de código comentados
- Diagramas de flujo
- Ejemplos de uso

#### 2. `RESUMEN_COMENTARIOS.md`
Resumen ejecutivo:
- Estadísticas de código
- Funciones principales
- Tabla de contenidos
- Quick reference

#### 3. `REPORTE_PRUEBAS.md`
Reporte detallado:
- Resultados de todos los tests
- Cobertura de código
- Vulnerabilidades probadas
- Ejemplos de pruebas

### Leer la Documentación

```bash
# Ver documentación completa
cat COMENTARIOS_CODIGO.md

# Ver resumen
cat RESUMEN_COMENTARIOS.md

# Ver reporte de pruebas
cat REPORTE_PRUEBAS.md
```

---

## 🐛 Solución de Problemas

### Error: "Puerto 3000 ya está en uso"
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID [PID] /F

# Linux/Mac
lsof -i :3000
kill -9 [PID]
```

### Error: "MongoDB connection failed"
```bash
# Verificar que MongoDB esté corriendo
# En Windows:
mongod

# En Docker:
docker run -d -p 27017:27017 mongo
```

### Tests fallando
```bash
# Limpiar node_modules e reinstalar
rm -r node_modules
npm install

# Ejecutar con debug
npm test -- --verbose
```

### Variable de entorno no definida
```bash
# Crear archivo .env
echo "DB_URI=mongodb://localhost:27017/virochat" > .env
echo "JWT_SECRET=tu_secreto_aqui" >> .env
echo "TOTP_SECRET=totp_secreto" >> .env
```

---

## 📊 Estadísticas del Proyecto

| Métrica | Valor |
|---------|-------|
| **Archivos Comentados** | 11+ archivos |
| **Líneas de Código Comentado** | 300+ líneas |
| **Tests Unitarios** | 69 tests |
| **Tests de Seguridad** | 13 tests |
| **Cobertura Mínima** | 70% |
| **Vulnerabilidades OWASP** | 6 categorías probadas |
| **Tiempo de Ejecución** | ~90 segundos |

---

## ✅ Checklist de Implementación

- [x] Código comentado (crypto, token, totp, fileType, models)
- [x] Tests unitarios (crypto, token, totp, fileType)
- [x] Tests de seguridad (OWASP A1, A02, A03, A05, A06)
- [x] Cobertura de código (>70%)
- [x] Detección MIME (magic numbers)
- [x] Análisis de esteganografía
- [x] Documentación completa
- [ ] Tests de integración (Supertest) - Pendiente
- [ ] Deployment a producción - Pendiente

---

## 🎯 Próximos Pasos

1. **Completar tests de integración**
   ```bash
   npm run test:integration
   ```

2. **Validar cobertura del 70%**
   ```bash
   npm run test:coverage
   ```

3. **Iniciar aplicación**
   ```bash
   npm start
   ```

4. **Hacer deploy a producción**
   - Docker Compose
   - Kubernetes (opcional)
   - Cloud provider (AWS, GCP, Azure)

---

## 📞 Soporte

Para problemas o preguntas sobre:
- **Tests**: Consulta `REPORTE_PRUEBAS.md`
- **Código**: Consulta `COMENTARIOS_CODIGO.md`
- **Seguridad**: Consulta `src/security/`

