const landingScreen = document.getElementById('landing');
const chatScreen = document.getElementById('chat');
const loginModal = document.getElementById('login-modal');
const openLoginBtn = document.getElementById('open-login');
const closeLoginBtn = document.getElementById('close-login');
const loginForm = document.getElementById('login-form');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const messagesContainer = document.getElementById('messages');
const usersList = document.getElementById('online-users');
const fileInput = document.getElementById('file-input');
const recentFilesList = document.getElementById('recent-files');
const currentUserLabel = document.getElementById('current-user');
const backButton = document.getElementById('back-to-landing');
const securityIndicator = document.getElementById('security-indicator');
const roomTitle = document.getElementById('room-title');
const roomSubtitle = document.getElementById('room-subtitle');
const roomIdInput = document.getElementById('room-id');
const roomPinInput = document.getElementById('room-pin');
const nicknameInput = document.getElementById('nickname');

const messageTemplate = document.getElementById('message-template');
const fileTemplate = document.getElementById('file-template');
const systemTemplate = document.getElementById('system-template');

let socket = null;
let cryptoKey = null;
let session = null;
let activeRoom = null;
const recentFiles = [];

const encoder = new TextEncoder();
const decoder = new TextDecoder();

openLoginBtn.addEventListener('click', () => {
  loginModal.classList.remove('hidden');
  roomIdInput.focus();
});

closeLoginBtn.addEventListener('click', () => {
  loginModal.classList.add('hidden');
});

backButton.addEventListener('click', () => {
  resetState();
  window.location.reload();
});

window.addEventListener('beforeunload', () => {
  if (socket) {
    socket.disconnect();
  }
});

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const roomId = roomIdInput.value.trim();
  const pin = roomPinInput.value.trim();
  const nickname = nicknameInput.value.trim();

  if (!roomId || !pin || !nickname) {
    showToast('Completa todos los campos para continuar.');
    return;
  }

  try {
    const response = await fetch('/api/rooms/access', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ roomId, pin, nickname }),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || 'No se pudo acceder a la sala.');
    }

    const payload = await response.json();
    await initializeSession(payload);
    loginModal.classList.add('hidden');
    landingScreen.classList.add('hidden');
    chatScreen.classList.remove('hidden');
    messageInput.focus();
  } catch (error) {
    showToast(error.message || 'Error al acceder a la sala.');
  }
});

messageForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !socket || !session || !cryptoKey) {
    return;
  }

  try {
    const payload = await encryptMessage(text);
    socket.emit('chat_message', {
      roomId: activeRoom.id,
      payload,
    });
    messageInput.value = '';
    messageInput.focus();
  } catch (error) {
    showToast('No se pudo cifrar el mensaje.');
    console.error(error);
  }
});

fileInput.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file || !session) {
    return;
  }

  try {
    updateSecurityIndicator('processing', 'Analizando archivo...');
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`/api/rooms/${activeRoom.id}/upload`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${session.token}`,
      },
      body: formData,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message || 'No se pudo compartir el archivo.');
    }

    const data = await response.json();
    socket.emit('file_shared', {
      roomId: activeRoom.id,
      url: data.url,
      name: data.originalName,
      filename: data.filename,
      size: data.size,
      mimetype: data.mimetype,
      entropy: data.entropy,
    });
    showToast('Archivo compartido con éxito.');
  } catch (error) {
    showToast(error.message || 'No se pudo compartir el archivo.');
  } finally {
    updateSecurityIndicator('secure', 'Cifrado activo');
    fileInput.value = '';
  }
});

async function initializeSession(payload) {
  session = {
    token: payload.sessionToken,
    nicknameHash: payload.user.nicknameHash,
    displayName: payload.user.displayName,
  };
  activeRoom = payload.room;
  cryptoKey = await importSessionKey(payload.sessionKey);

  currentUserLabel.textContent = formatHash(session.nicknameHash);
  roomTitle.textContent = `Sala ${formatHash(activeRoom.id)}`;
  roomSubtitle.textContent =
    activeRoom.type === 'multimedia'
      ? 'Canal multimedia cifrado con monitoreo de archivos'
      : 'Canal de texto cifrado de extremo a extremo';
  updateSecurityIndicator('secure', 'Cifrado activo');

  const uploadWrapper = fileInput.closest('label');
  if (activeRoom.type === 'multimedia') {
    fileInput.removeAttribute('disabled');
    uploadWrapper?.classList.remove('disabled');
  } else {
    fileInput.setAttribute('disabled', 'true');
    uploadWrapper?.classList.add('disabled');
  }

  initializeSocket();
}

function resetState() {
  session = null;
  activeRoom = null;
  cryptoKey = null;
  if (socket) {
    socket.disconnect();
    socket = null;
  }
  currentUserLabel.textContent = '--';
  messagesContainer.innerHTML = '';
  usersList.innerHTML = '';
  recentFiles.length = 0;
  recentFilesList.innerHTML = '';
  loginForm.reset();
}

async function initializeSocket() {
  if (!session) return;
  if (socket) {
    socket.disconnect();
  }

  socket = io({
    auth: { token: session.token },
    transports: ['websocket'],
  });

  socket.on('connect', () => {
    updateSecurityIndicator('secure', 'Cifrado activo');
  });

  socket.on('connect_error', (error) => {
    updateSecurityIndicator('warning', 'Reintentando conexión...');
    showToast(error.message || 'No se pudo conectar con el chat.');
  });

  socket.on('disconnect', () => {
    updateSecurityIndicator('warning', 'Sin conexión');
  });

  socket.on('user_list', (users) => {
    renderUserList(users || []);
  });

  socket.on('chat_message', async (message) => {
    if (!message || !message.payload) return;
    let decryptedText = 'Mensaje cifrado';
    try {
      decryptedText = await decryptMessage(message.payload);
    } catch (error) {
      console.error('No se pudo descifrar el mensaje', error);
    }
    renderMessage({ ...message, text: decryptedText });
  });

  socket.on('file_shared', (fileMessage) => {
    renderFileMessage(fileMessage);
  });

  socket.on('system_message', (systemMessage) => {
    renderSystemMessage(systemMessage);
  });

  socket.on('security_alert', (alert) => {
    updateSecurityIndicator('warning', 'Alerta de seguridad');
    renderSecurityAlert(alert);
  });
}

function renderUserList(users) {
  usersList.innerHTML = '';

  if (!Array.isArray(users) || users.length === 0) {
    const li = document.createElement('li');
    li.textContent = 'No hay usuarios conectados';
    li.classList.add('empty');
    usersList.appendChild(li);
    return;
  }

  users.forEach((user) => {
    const li = document.createElement('li');
    const hash = document.createElement('span');
    hash.textContent = formatHash(user.nicknameHash);
    hash.classList.add('hash-badge');
    li.appendChild(hash);
    if (user.connectedAt) {
      const meta = document.createElement('span');
      meta.textContent = new Date(user.connectedAt).toLocaleTimeString('es-ES', {
        hour: '2-digit',
        minute: '2-digit',
      });
      meta.classList.add('user-mail');
      li.appendChild(meta);
    }
    usersList.appendChild(li);
  });
}

function renderMessage(message) {
  const template = messageTemplate.content.cloneNode(true);
  template.querySelector('.message-author').textContent = formatHash(message.sender);
  template.querySelector('.message-time').textContent = formatTime(message.timestamp);
  template.querySelector('.message-text').textContent = message.text || 'Mensaje cifrado';
  messagesContainer.appendChild(template);
  scrollMessagesToBottom();
}

function renderFileMessage(fileMessage) {
  const template = fileTemplate.content.cloneNode(true);
  template.querySelector('.message-author').textContent = formatHash(fileMessage.sender);
  template.querySelector('.message-time').textContent = formatTime(fileMessage.timestamp);
  const link = template.querySelector('.file-link');
  link.href = fileMessage.url;
  link.setAttribute('download', fileMessage.name || fileMessage.filename);
  template.querySelector('.file-name').textContent = fileMessage.name || 'Archivo';
  template.querySelector('.file-size').textContent = humanFileSize(fileMessage.size);
  messagesContainer.appendChild(template);
  addRecentFile(fileMessage);
  scrollMessagesToBottom();
}

function renderSystemMessage(systemMessage) {
  const template = systemTemplate.content.cloneNode(true);
  const text = template.querySelector('.message-text');

  if (systemMessage.type === 'join') {
    text.textContent = `${formatHash(systemMessage.user)} se ha conectado`;
  } else if (systemMessage.type === 'leave') {
    text.textContent = `${formatHash(systemMessage.user)} se ha desconectado`;
  } else {
    text.textContent = systemMessage.message || 'Notificación del sistema';
  }

  messagesContainer.appendChild(template);
  scrollMessagesToBottom();
}

function renderSecurityAlert(alert) {
  const template = systemTemplate.content.cloneNode(true);
  const text = template.querySelector('.message-text');
  const details = alert?.entropy ? ` (entropía: ${alert.entropy.toFixed(2)})` : '';
  text.textContent = `Alerta de seguridad: ${alert?.message || 'Actividad sospechosa detectada'}${details}`;
  messagesContainer.appendChild(template);
  scrollMessagesToBottom();
  showToast(alert?.message || 'Se detectó actividad sospechosa.');
}

function addRecentFile(fileMessage) {
  if (!fileMessage) return;
  recentFiles.unshift(fileMessage);
  if (recentFiles.length > 6) {
    recentFiles.pop();
  }

  recentFilesList.innerHTML = '';

  recentFiles.forEach((file) => {
    const li = document.createElement('li');
    const link = document.createElement('a');
    link.href = file.url;
    link.textContent = `${formatHash(file.sender)} · ${file.name || file.filename}`;
    link.setAttribute('download', file.name || file.filename);
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    const meta = document.createElement('span');
    meta.textContent = humanFileSize(file.size);
    meta.classList.add('user-mail');
    li.appendChild(link);
    li.appendChild(meta);
    recentFilesList.appendChild(li);
  });
}

function formatTime(timestamp) {
  if (!timestamp) return '';
  const date = new Date(timestamp);
  return date.toLocaleTimeString('es-ES', {
    hour: '2-digit',
    minute: '2-digit',
  });
}

function humanFileSize(size) {
  if (!size) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const exponent = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1);
  const value = size / Math.pow(1024, exponent);
  return `${value.toFixed(value < 10 && exponent > 0 ? 1 : 0)} ${units[exponent]}`;
}

function scrollMessagesToBottom() {
  messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function showToast(message) {
  if (!message) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.textContent = message;
  document.body.appendChild(toast);
  requestAnimationFrame(() => {
    toast.classList.add('visible');
  });
  setTimeout(() => {
    toast.classList.remove('visible');
    toast.addEventListener('transitionend', () => {
      toast.remove();
    });
  }, 3200);
}

function formatHash(hash) {
  if (!hash) return '---';
  return hash.replace(/[^A-Za-z0-9]/g, '').slice(0, 10) || '---';
}

function updateSecurityIndicator(state, message) {
  if (!securityIndicator) return;
  const dot = securityIndicator.querySelector('.status-dot');
  const label = securityIndicator.querySelector('.security-label');
  if (message && label) {
    label.textContent = message;
  }
  if (!dot) return;
  dot.classList.remove('secure', 'warning');
  if (state === 'secure') {
    dot.classList.add('secure');
  } else {
    dot.classList.add('warning');
  }
}

async function importSessionKey(base64Key) {
  const raw = base64ToArrayBuffer(base64Key);
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptMessage(plainText) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    cryptoKey,
    encoder.encode(plainText)
  );
  return {
    iv: arrayBufferToBase64(iv.buffer),
    content: arrayBufferToBase64(encrypted),
  };
}

async function decryptMessage(payload) {
  const iv = base64ToArrayBuffer(payload.iv);
  const content = base64ToArrayBuffer(payload.content);
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: new Uint8Array(iv),
    },
    cryptoKey,
    content
  );
  return decoder.decode(decrypted);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return buffer;
}
