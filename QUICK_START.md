# ⚡ Quick Start - ViroChat

> Levanta la aplicación y ejecuta pruebas en 5 minutos

---

## 🚀 Paso 1: Instalación (2 minutos)

```bash
# 1. Entra al directorio del proyecto
cd chat-proyect

# 2. Instala dependencias
npm install

# 3. Configura variables de entorno (opcional)
# Editar .env con valores reales
```

---

## 🧪 Paso 2: Ejecutar Pruebas (2 minutos)

```bash
# Opción A: Todas las pruebas (recomendado)
npm test

# Resultado esperado:
# ✓ Test Suites: 5 passed
# ✓ Tests: 82 passed
# ✓ Time: ~90 seconds
```

### Otras opciones:

```bash
# Solo pruebas unitarias
npm run test:unit

# Solo pruebas de seguridad (OWASP Top 10)
npm run test:security

# Con reporte de cobertura
npm run test:coverage

# Modo watch (desarrollo)
npm run test:watch
```

---

## ▶️ Paso 3: Levanta la Aplicación (1 minuto)

```bash
# Opción A: Ejecución directa
npm start

# Resultado esperado:
# Server listening on port 3000
# Database connected
# Socket.IO initialized
# → Abre: http://localhost:3000
```

### Alternativa con Docker:

```bash
# Opción B: Docker Compose (todo automático)
docker-compose up

# Resultado esperado:
# - Node.js en http://localhost:3000
# - MongoDB en localhost:27017
# - Volúmenes persistentes configurados
```

---

## 📋 Comandos Rápidos

```bash
# Ver todos los tests
npm test

# Ver pruebas de seguridad
npm run test:security

# Reporte de cobertura
npm run test:coverage

# Levanta el servidor
npm start

# Modo desarrollo (auto-reload)
npm run dev

# Limpiar
rm -r node_modules
npm install
```

---

## 📖 Documentación

| Archivo | Contenido |
|---------|-----------|
| `REPORTE_PRUEBAS.md` | 📊 Todos los tests y resultados |
| `GUIA_EJECUCION.md` | 📘 Guía completa de instalación y uso |
| `ANALISIS_SEGURIDAD.md` | 🔐 Análisis de vulnerabilidades OWASP |
| `COMENTARIOS_CODIGO.md` | 💬 Código comentado completamente |
| `RESUMEN_COMENTARIOS.md` | 📝 Resumen ejecutivo |

---

## ✅ Verificar Instalación

```bash
# Debería ver:
npm test
# Test Suites: 5 passed, 5 total ✓
# Tests: 82 passed, 82 total ✓
```

---

## 🎯 Tests Disponibles

### Unitarios (69 tests)
- ✅ Criptografía AES-256-GCM (20 tests)
- ✅ JWT HMAC-SHA256 (16 tests)
- ✅ TOTP 2FA RFC 6238 (15 tests)
- ✅ Detección MIME (18 tests)

### Seguridad (13 tests)
- ✅ OWASP A1: Inyección (3 tests)
- ✅ OWASP A02: Autenticación (3 tests)
- ✅ OWASP A03: Datos (2 tests)
- ✅ OWASP A05: Acceso (2 tests)
- ✅ OWASP A06: Información Sensible (3 tests)

---

## 🔍 Verificar Módulos de Seguridad

```javascript
// 1. Cifrado
const crypto = require('./src/security/crypto');
crypto.encryptText('Hola', secret); // ✓

// 2. Tokens
const token = require('./src/security/token');
token.signToken({ user: 'admin' }, secret); // ✓

// 3. TOTP
const totp = require('./src/security/totp');
totp.verifyTotp('123456', secret); // ✓

// 4. Tipos de Archivo
const fileType = require('./src/security/fileType');
fileType.detectFileType('/file.png'); // ✓
```

---

## 🐛 Si Algo Falla

| Problema | Solución |
|----------|----------|
| Port 3000 in use | `npm run test` primero, luego `npm start` |
| MongoDB not found | Ver `docker-compose.yml` o instalar MongoDB local |
| Tests failing | `npm install` nuevamente |
| Module not found | `npm install` y verificar node_modules |

---

## 📊 Resultados Esperados

```
PASS  tests/unit/crypto.test.js
PASS  tests/unit/token.test.js
PASS  tests/unit/totp.test.js
PASS  tests/unit/fileType.test.js
PASS  tests/security/security.test.js

Test Suites: 5 passed, 5 total
Tests:       82 passed, 82 total
Snapshots:   0 total
Time:        ~90 seconds
```

✅ **¡Listo para usar!**

---

**Última actualización**: 18 de noviembre de 2025
