# ViroChat

ViroChat es un chat en tiempo real inspirado en el estilo cyberpunk del mockup original. Permite conectar personas desde cualquier lugar, registrar su asistencia en MongoDB y compartir archivos directamente desde la sala de conversación.

## Características

- Pantalla de bienvenida con acceso mediante formulario emergente.
- Registro de nombre, correo y fecha de ingreso en MongoDB (se permiten duplicados para múltiples asistencias).
- Sala de chat global en tiempo real desarrollada con Socket.IO.
- Envío y descarga de archivos compartidos con el resto de participantes.
- Lista dinámica de usuarios conectados y galería de archivos recientes.
- Interfaz responsive con estética neón y efectos glassmorphism.
- Despliegue sencillo mediante Docker y docker-compose.

## Requisitos previos

- Node.js 20+
- npm
- MongoDB (puede ser la instancia Atlas proporcionada o un contenedor local)
- Opcional: Docker y docker-compose

## Configuración

1. Copia el archivo de variables de entorno y ajusta los valores según tu entorno:

   ```bash
   cp .env.example .env
   ```

2. Instala las dependencias (requiere acceso a internet para descargar los paquetes de npm):

   ```bash
   npm install
   ```

3. Inicia el servidor en modo desarrollo:

   ```bash
   npm run dev
   ```

   O en modo producción:

   ```bash
   npm start
   ```

4. Abre <http://localhost:3000> en tu navegador, ingresa tu nombre y correo y comienza a chatear.

## Uso de Docker

1. Construye y levanta los contenedores:

   ```bash
   docker compose up --build
   ```

   El servicio `app` se conectará a la URI definida en la variable `MONGODB_URI`. Por defecto utiliza la base local `mongodb://mongo:27017/virochat`. Si quieres usar tu clúster Atlas, crea un archivo `.env` y coloca la URI proporcionada.

2. Los archivos compartidos se almacenan en la carpeta `uploads/`, la cual se monta como volumen en el contenedor para que persista entre reinicios.

## Estructura de carpetas

```
├── public/
│   ├── assets/           # Recursos gráficos
│   ├── css/              # Estilos del frontend
│   ├── js/               # Lógica del cliente
│   └── index.html        # Interfaz principal
├── src/
│   └── models/           # Esquemas de Mongoose
├── uploads/              # Carpeta de archivos compartidos (se crea automáticamente)
├── server.js             # Servidor Express + Socket.IO
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Variables de entorno

| Variable      | Descripción                                                         |
| ------------- | ------------------------------------------------------------------- |
| `PORT`        | Puerto HTTP que utiliza el servidor Express.                        |
| `MONGODB_URI` | URI de conexión a MongoDB (Atlas o instancia local en docker-compose). |

## Notas

- La colección de asistencia permite duplicados para registrar múltiples ingresos del mismo correo.
- Si deseas personalizar la estética, modifica los estilos en `public/css/styles.css`.
- Para un entorno seguro en producción, configura límites de tamaño en la carga de archivos y usa HTTPS.

¡Disfruta conectando a tu comunidad con ViroChat!
