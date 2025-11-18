# ViroChat - Chat Seguro con Detección de Esteganografía

ViroChat es un chat en tiempo real cifrado de extremo a extremo con análisis avanzado de seguridad. Implementa criptografía AES-256-GCM, autenticación de dos factores (TOTP), y detección de esteganografía mediante análisis de entropía, binwalk y steghide.

---

## 📋 Tabla de Contenidos

1. [Características](#características)
2. [Funcionalidad del Sistema](#funcionalidad-del-sistema-de-chat)
3. [Manejo de Concurrencia](#manejo-de-concurrencia)
4. [Pruebas y Cobertura](#pruebas-y-cobertura)
5. [Instalación](#instalación)
6. [Configuración](#configuración)

---

## ✨ Características

- **Cifrado E2E**: AES-256-GCM en cliente y servidor
- **Autenticación Fuerte**: PBKDF2-SHA256 + TOTP 2FA
- **Análisis de Seguridad**: Detección de esteganografía con entropía, binwalk, LSB y pruebas de extracción Steghide
- **Rate Limiting**: 100 solicitudes/minuto por IP
- **Auditoría Completa**: HMAC-SHA256 de eventos
- **Salas Seguras**: PIN protegido, tipos text/multimedia
- **Detección de Tipos MIME**: Magic numbers vs extensión
- **Socket.IO Real-time**: Comunicación instantánea
- **MongoDB**: Registro de eventos y auditoría
- **Interfaz Responsive**: Estética neón con glassmorphism

---

## 🔐 Funcionalidad del Sistema de Chat con Detección de Esteganografía y Mecanismos de Seguridad

### Flujo de Autenticación y Seguridad

**Diagrama de Secuencia:**

![Diagrama](img/diagramaflujo.png)

### Detalles de Seguridad

#### **1. Autenticación Admin**
- Usuario + Contraseña + Token TOTP (2FA)
- Contraseñas hasheadas con PBKDF2 (120k iteraciones)
- Timing-safe comparison para evitar timing attacks
- Registro auditado de intentos fallidos

#### **2. Autenticación de Sala**
- PIN protegido con PBKDF2-SHA256
- Fingerprinting de dispositivo (IP + User-Agent)
- Prevención de múltiples conexiones simultáneas
- Validación de nickname (3-32 caracteres)

#### **3. Cifrado de Mensajes**
- AES-256-GCM en navegador (Web Crypto API)
- IV aleatorio de 12 bytes por mensaje
- Tag de autenticación de 128 bits
- Intercambio de clave de sesión cifrada

#### **4. Detección de Esteganografía**
- Análisis de entropía de Shannon (0-8 bits)
- Umbral sospechoso: ≥7.985 + bytes finales
- Escaneo binwalk para archivos ocultos
- Heurística LSB sobre megapíxeles (detección de patrones uniformes y canales RGB convertidos)
- Probing de **Steghide** para detectar contenedores cifrados o protegidos con contraseña
- Validación de magic numbers vs extensión

#### **5. Validación de Archivos**
- Detección de tipo MIME real (no confiar en extensión)
- Límite de tamaño configurable (máx. 50 MB)
- Tipos permitidos: JPEG, PNG, GIF, PDF, TXT, ZIP
- Rechazo automático de archivos sospechosos

---

## ⚡ Manejo de Concurrencia

ViroChat implementa múltiples mecanismos para manejar concurrencia de manera segura:

### Mecanismos Implementados

#### **1. Session Registry**
```javascript
Map<roomId, Map<sessionId, sessionData>>