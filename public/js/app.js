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

const messageTemplate = document.getElementById('message-template');
const fileTemplate = document.getElementById('file-template');
const systemTemplate = document.getElementById('system-template');

let socket = null;
let currentUser = null;
const recentFiles = [];

openLoginBtn.addEventListener('click', () => {
  loginModal.classList.remove('hidden');
  document.getElementById('name').focus();
});

closeLoginBtn.addEventListener('click', () => {
  loginModal.classList.add('hidden');
});

backButton.addEventListener('click', () => {
  window.location.reload();
});

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(loginForm);
  const name = formData.get('name').trim();
  const email = formData.get('email').trim();

  if (!name || !email) {
    return;
  }

  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name, email }),
    });

    if (!response.ok) {
      throw new Error('No se pudo registrar tu ingreso. Intenta nuevamente.');
    }

    const payload = await response.json();
    currentUser = {
      name: payload.name,
      email: payload.email,
    };

    currentUserLabel.textContent = currentUser.name;
    landingScreen.classList.add('hidden');
    loginModal.classList.add('hidden');
    chatScreen.classList.remove('hidden');

    initializeSocket();
    messageInput.focus();
  } catch (error) {
    showToast(error.message || 'Hubo un problema al conectar.');
  }
});

messageForm.addEventListener('submit', (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();

  if (!text || !socket) {
    return;
  }

  socket.emit('chat_message', {
    text,
    sender: currentUser?.name || 'Anónimo',
  });

  messageInput.value = '';
  messageInput.focus();
});

fileInput.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file || !socket) {
    return;
  }

  try {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/api/upload', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      throw new Error('No se pudo enviar el archivo.');
    }

    const data = await response.json();
    socket.emit('file_shared', {
      sender: currentUser?.name || 'Anónimo',
      url: data.url,
      name: data.originalName,
      size: data.size,
      mimetype: data.mimetype,
    });

    fileInput.value = '';
  } catch (error) {
    showToast(error.message || 'No se pudo compartir el archivo.');
  }
});

function initializeSocket() {
  socket = io();

  socket.on('connect_error', () => {
    showToast('No se pudo conectar con el chat.');
  });

  socket.on('connect', () => {
    if (currentUser) {
      socket.emit('join', currentUser);
    }
  });

  socket.on('user_list', (users) => {
    renderUserList(users || []);
  });

  socket.on('chat_message', (message) => {
    renderMessage(message);
  });

  socket.on('file_shared', (fileMessage) => {
    renderFileMessage(fileMessage);
  });

  socket.on('system_message', (systemMessage) => {
    renderSystemMessage(systemMessage);
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
    const name = document.createElement('span');
    name.textContent = user.name;
    const email = document.createElement('span');
    email.textContent = user.email;
    email.classList.add('user-mail');
    li.appendChild(name);
    li.appendChild(email);
    usersList.appendChild(li);
  });
}

function renderMessage(message) {
  if (!message) return;
  const template = messageTemplate.content.cloneNode(true);
  template.querySelector('.message-author').textContent = message.sender || 'Usuario';
  template.querySelector('.message-time').textContent = formatTime(message.timestamp);
  template.querySelector('.message-text').textContent = message.text;
  messagesContainer.appendChild(template);
  scrollMessagesToBottom();
}

function renderFileMessage(fileMessage) {
  const template = fileTemplate.content.cloneNode(true);
  template.querySelector('.message-author').textContent = fileMessage.sender || 'Usuario';
  template.querySelector('.message-time').textContent = formatTime(fileMessage.timestamp);
  const link = template.querySelector('.file-link');
  link.href = fileMessage.url;
  link.setAttribute('download', fileMessage.name);
  template.querySelector('.file-name').textContent = fileMessage.name;
  template.querySelector('.file-size').textContent = humanFileSize(fileMessage.size);
  messagesContainer.appendChild(template);
  addRecentFile(fileMessage);
  scrollMessagesToBottom();
}

function renderSystemMessage(systemMessage) {
  const template = systemTemplate.content.cloneNode(true);
  const text = template.querySelector('.message-text');

  if (systemMessage.type === 'join') {
    text.textContent = `${systemMessage.user} se ha conectado`;
  } else if (systemMessage.type === 'leave') {
    text.textContent = `${systemMessage.user} se ha desconectado`;
  } else {
    text.textContent = systemMessage.message || '';
  }

  messagesContainer.appendChild(template);
  scrollMessagesToBottom();
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
    link.textContent = file.name;
    link.setAttribute('download', file.name);
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
