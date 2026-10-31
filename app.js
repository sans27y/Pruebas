/* =========================================================
   Top 10 OST - lógica compartida (sin backend, solo localStorage)
   ========================================================= */

var MAX_AUDIO_BYTES = 2 * 1024 * 1024; // RNF06: 2 MB por canción

/* ---------- SHA-256 (RNF01: no guardar contraseñas en texto plano) ---------- */
function sha256(ascii) {
  function rr(v, a) { return (v >>> a) | (v << (32 - a)); }
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbc5,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a5,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0x5b9cca4f,0x682e6ff3,0x748f82ee,
    0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

  ascii = unescape(encodeURIComponent(ascii));
  var l = ascii.length, words = [], i, j;

  for (i = 0; i < l; i++) {
    words[i >> 2] |= ascii.charCodeAt(i) << (24 - (i % 4) * 8);
  }

  words[l >> 2] |= 0x80 << (24 - (l % 4) * 8);

  var total = (((l + 8) >> 6) << 4) + 16;

  for (i = 0; i < total; i++) {
    if (words[i] === undefined) words[i] = 0;
  }

  words[total - 1] = l * 8;

  for (j = 0; j < words.length; j += 16) {
    var w = words.slice(j, j + 16), a = H.slice(0);

    for (i = 0; i < 64; i++) {
      var w15 = w[i - 15], w2 = w[i - 2];

      if (i >= 16) {
        w[i] = (w[i - 16] +
          (rr(w15, 7) ^ rr(w15, 18) ^ (w15 >>> 3)) +
          w[i - 7] +
          (rr(w2, 17) ^ rr(w2, 19) ^ (w2 >>> 10))) | 0;
      }

      var t1 = (a[7] +
        (rr(a[4], 6) ^ rr(a[4], 11) ^ rr(a[4], 25)) +
        ((a[4] & a[5]) ^ (~a[4] & a[6])) +
        K[i] + (w[i] | 0)) | 0;

      var t2 = ((rr(a[0], 2) ^ rr(a[0], 13) ^ rr(a[0], 22)) +
        ((a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]))) | 0;

      a = [
        (t1 + t2) | 0,
        a[0],
        a[1],
        a[2],
        (a[3] + t1) | 0,
        a[4],
        a[5],
        a[6]
      ];
    }

    for (i = 0; i < 8; i++) {
      H[i] = (H[i] + a[i]) | 0;
    }
  }

  var out = '';

  for (i = 0; i < 8; i++) {
    out += ('00000000' + (H[i] >>> 0).toString(16)).slice(-8);
  }

  return out;
}

/* ---------- Acceso seguro a localStorage ---------- */
var Store = {
  get: function (key, def) {
    try {
      var raw = localStorage.getItem(key);
      return raw === null ? def : JSON.parse(raw);
    } catch (e) {
      return def;
    }
  },

  getRaw: function (key) {
    try {
      return localStorage.getItem(key);
    } catch (e) {
      return null;
    }
  },

  set: function (key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
      return true;
    } catch (e) {
      return false;
    }
  },

  setRaw: function (key, value) {
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      return false;
    }
  },

  remove: function (key) {
    try {
      localStorage.removeItem(key);
    } catch (e) {}
  }
};

/* ---------- Autenticación ---------- */
var Auth = {
  users: function () {
    return Store.get('usuarios', {});
  },

  register: function (name, pass) {
    var key = name.toLowerCase();
    var users = this.users();

    if (users[key]) {
      return {
        ok: false,
        msg: 'El nombre de usuario ya existe. Elige otro.'
      };
    }

    var salt = Math.random().toString(36).slice(2) +
      Date.now().toString(36);

    users[key] = {
      nombre: name,
      salt: salt,
      hash: sha256(salt + ':' + pass)
    };

    if (!Store.set('usuarios', users)) {
      return {
        ok: false,
        msg: 'No se pudo guardar la cuenta (almacenamiento lleno).'
      };
    }

    return { ok: true };
  },

  login: function (name, pass) {
    var u = this.users()[name.toLowerCase()];

    if (!u || u.hash !== sha256(u.salt + ':' + pass)) {
      return {
        ok: false,
        msg: 'Usuario o contraseña incorrectos'
      };
    }

    Store.setRaw('sesion', 'activa');
    Store.setRaw('usuario_actual', u.nombre);

    return { ok: true };
  },

  current: function () {
    if (Store.getRaw('sesion') !== 'activa') return null;

    var name = Store.getRaw('usuario_actual');

    if (!name || !this.users()[name.toLowerCase()]) {
      return null;
    }

    return name;
  },

  logout: function () {
    Store.remove('sesion');
    Store.remove('usuario_actual');
  },

  requireLogin: function () {
    if (this.current()) return true;

    alert('Debes iniciar sesión para acceder a esta función.');
    window.location.href = 'index.html';

    return false;
  }
};

/* ---------- Foto de perfil ---------- */
var DEFAULT_PFP = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 80"><rect width="80" height="80" fill="#131a22"/>' +
  '<circle cx="40" cy="31" r="14" fill="#00ceff" opacity=".7"/><path d="M12 80c2-18 14-28 28-28s26 10 28 28z" fill="#00ceff" opacity=".7"/></svg>'
);

var Profile = {
  get: function (user) {
    return (user && Store.getRaw('foto_' + user.toLowerCase())) || DEFAULT_PFP;
  },

  set: function (user, file, cb) {
    if (!file.type || file.type.indexOf('image/') !== 0) {
      cb('El archivo seleccionado no es una imagen válida.');
      return;
    }

    var reader = new FileReader();

    reader.onload = function (e) {
      if (!Store.setRaw('foto_' + user.toLowerCase(), e.target.result)) {
        cb('No se pudo guardar la imagen (es demasiado grande para el almacenamiento local).');
      } else {
        cb(null);
      }
    };

    reader.onerror = function () {
      cb('No se pudo leer la imagen.');
    };

    reader.readAsDataURL(file);
  }
};

/* ---------- Canciones subidas por usuarios ---------- */
var Songs = {
  list: function () {
    return Store.get('canciones_subidas', []);
  },

  audio: function (id) {
    return Store.getRaw('audio_' + id);
  },

  cover: function (id) {
    return Store.getRaw('portada_' + id) || '';
  },

  validateFile: function (file) {
    if (!file) {
      return 'Debes seleccionar un archivo de audio.';
    }

    var isMp3Name = /\.mp3$/i.test(file.name);
    var okType = file.type === '' ||
      file.type === 'audio/mpeg' ||
      file.type === 'audio/mp3';

    if (!isMp3Name || !okType) {
      return 'Formato no permitido. Solo se aceptan archivos .mp3. Selecciona otro archivo.';
    }

    if (file.size > MAX_AUDIO_BYTES) {
      return 'El archivo excede el tamaño máximo de 2 MB. Selecciona otro archivo.';
    }

    return null;
  },

  validateCover: function (file) {
    if (!file) {
      return 'Debes seleccionar una imagen de portada.';
    }

    if (!file.type || file.type.indexOf('image/') !== 0) {
      return 'La portada debe ser una imagen válida.';
    }

    if (file.size > 2 * 1024 * 1024) {
      return 'La portada no puede superar los 2 MB.';
    }

    return null;
  },

  add: function (meta, audioData, coverData) {
    var id = 'user-' + Date.now() + '-' +
      Math.random().toString(36).slice(2, 6);

    if (!Store.setRaw('audio_' + id, audioData)) {
      return false;
    }

    if (coverData && !Store.setRaw('portada_' + id, coverData)) {
      Store.remove('audio_' + id);
      return false;
    }

    var all = this.list();

    meta.id = id;
    all.push(meta);

    if (!Store.set('canciones_subidas', all)) {
      Store.remove('audio_' + id);
      Store.remove('portada_' + id);
      return false;
    }

    return true;
  }
};

/* ---------- Calificaciones por canción ---------- */
var Ratings = {
  getAll: function () {
    return Store.get('calificaciones', {});
  },

  add: function (songId, user, stars) {
    var all = this.getAll();

    all[songId] = all[songId] || {};
    all[songId][user.toLowerCase()] = stars;

    return Store.set('calificaciones', all);
  },

  get: function (songId) {
    var ratings = this.getAll()[songId] || {};
    var values = Object.values(ratings);

    var total = values.reduce(function (sum, n) {
      return sum + n;
    }, 0);

    return {
      promedio: values.length ? (total / values.length).toFixed(1) : '0.0',
      votos: values.length,
      usuarios: ratings
    };
  }
};

function buildRating(songId, onRate) {
  var user = Auth.current();
  var box = el('div', { class: 'rating-box' });
  var info = el('p', { class: 'rating-info' });
  var stars = el('div', { class: 'rating-stars' });

  function refresh() {
    var data = Ratings.get(songId);
    var actual = user ? (data.usuarios[user.toLowerCase()] || 0) : 0;

    info.textContent = '★ ' + data.promedio + ' / 5 · ' +
      data.votos + ' votos';

    stars.innerHTML = '';

    for (var i = 1; i <= 5; i++) {
      (function (n) {
        var btn = el('button', {
          type: 'button',
          class: 'rating-star' + (n <= actual ? ' selected' : ''),
          text: '★',
          'aria-label': 'Calificar con ' + n + ' estrellas',
          title: n + ' estrellas'
        });

        btn.disabled = !user;

        btn.addEventListener('click', function () {
          if (!Ratings.add(songId, user, n)) {
            alert('No se pudo guardar la calificación.');
            return;
          }

          refresh();

          if (typeof onRate === 'function') {
            onRate();
          }
        });

        stars.appendChild(btn);
      })(i);
    }
  }

  refresh();

  box.appendChild(info);
  box.appendChild(stars);

  if (!user) {
    box.appendChild(el('p', {
      class: 'muted',
      text: 'Inicia sesión para calificar.'
    }));
  }

  return box;
}

/* ---------- Comentarios ---------- */
var Comments = {
  MAX: 500,

  get: function (songId) {
    return (Store.get('comentarios', {})[songId]) || [];
  },

  add: function (songId, user, text) {
    var all = Store.get('comentarios', {});

    (all[songId] = all[songId] || []).push({
      usuario: user,
      texto: text,
      fecha: new Date().toLocaleString('es-CO')
    });

    return Store.set('comentarios', all);
  }
};

/* ---------- Utilidades de interfaz ---------- */
function el(tag, attrs, children) {
  var n = document.createElement(tag);
  attrs = attrs || {};

  for (var k in attrs) {
    if (k === 'text') {
      n.textContent = attrs[k];
    } else if (k === 'class') {
      n.className = attrs[k];
    } else {
      n.setAttribute(k, attrs[k]);
    }
  }

  (children || []).forEach(function (c) {
    if (c) n.appendChild(c);
  });

  return n;
}

/* ---------- Reproductor personalizado ---------- */

// Guarda el reproductor que está sonando actualmente.
var activeAudioPlayer = null;

function buildAudio(src) {
  var wrap = el('div', { class: 'audio-block' });
  var row = el('div', { class: 'audio-wrap' });

  var button = el('button', {
    class: 'audio-play-btn',
    type: 'button',
    title: 'Reproducir canción',
    'aria-label': 'Reproducir canción'
  });

  button.textContent = '▶';

  var audio = el('audio', { preload: 'metadata' });

  var msg = el('p', {
    class: 'msg msg-error',
    role: 'alert',
    hidden: ''
  });

  function setButtonPlaying(playing) {
    button.textContent = playing ? 'Ⅱ' : '▶';

    button.classList.toggle('is-playing', playing);

    button.title = playing
      ? 'Pausar canción'
      : 'Reproducir canción';

    button.setAttribute('aria-label', button.title);
  }

  function fail() {
    msg.textContent = 'Error de reproducción: no se pudo cargar el archivo de audio.';
    msg.removeAttribute('hidden');
    setButtonPlaying(false);
  }

  if (!src) {
    fail();
    button.disabled = true;
  } else {
    var source = el('source');

    source.addEventListener('error', fail);
    audio.addEventListener('error', fail);

    source.setAttribute('src', src);
    audio.appendChild(source);
  }

  button.addEventListener('click', function () {
    if (!src) return;

    // Si otra canción está sonando, la pausa y reinicia.
    if (activeAudioPlayer && activeAudioPlayer !== audio) {
      activeAudioPlayer.pause();
      activeAudioPlayer.currentTime = 0;

      if (activeAudioPlayer._playButton) {
        activeAudioPlayer._playButton.textContent = '▶';

        activeAudioPlayer._playButton.classList.remove('is-playing');

        activeAudioPlayer._playButton.title = 'Reproducir canción';

        activeAudioPlayer._playButton.setAttribute(
          'aria-label',
          'Reproducir canción'
        );
      }
    }

    // Reproducir o pausar la canción seleccionada.
    if (audio.paused) {
      activeAudioPlayer = audio;
      audio._playButton = button;

      var playRequest = audio.play();

      if (playRequest && typeof playRequest.catch === 'function') {
        playRequest.catch(fail);
      }
    } else {
      audio.pause();
    }
  });

  audio.addEventListener('play', function () {
    activeAudioPlayer = audio;
    setButtonPlaying(true);
  });

  audio.addEventListener('pause', function () {
    setButtonPlaying(false);

    if (activeAudioPlayer === audio) {
      activeAudioPlayer = null;
    }
  });

  audio.addEventListener('ended', function () {
    setButtonPlaying(false);

    if (activeAudioPlayer === audio) {
      activeAudioPlayer = null;
    }
  });

  row.appendChild(button);
  row.appendChild(audio);

  wrap.appendChild(row);
  wrap.appendChild(msg);

  return wrap;
}

/* ---------- Comentarios: todos los ven, solo con sesión se comenta ---------- */
function buildComments(songId) {
  var det = el('details', { class: 'comments' });
  var sum = el('summary');
  var list = el('div', { class: 'comment-list' });

  det.appendChild(sum);
  det.appendChild(list);

  function refresh() {
    var items = Comments.get(songId);

    sum.textContent = '💬 Comentarios (' + items.length + ')';
    list.innerHTML = '';

    if (!items.length) {
      list.appendChild(el('p', {
        class: 'muted',
        text: 'Aún no hay comentarios en esta canción.'
      }));
    }

    items.forEach(function (c) {
      list.appendChild(el('div', { class: 'comment' }, [
        el('div', { class: 'comment-head' }, [
          el('strong', { text: c.usuario }),
          el('span', {
            class: 'muted',
            text: ' · ' + c.fecha
          })
        ]),
        el('p', { text: c.texto })
      ]));
    });
  }

  refresh();

  var user = Auth.current();

  if (!user) {
    det.appendChild(el('p', {
      class: 'muted comment-login'
    }, [
      document.createTextNode('Inicia sesión o regístrate para comentar. '),
      el('a', {
        href: 'index.html',
        text: 'Iniciar sesión'
      })
    ]));

    return det;
  }

  var ta = el('textarea', {
    placeholder: 'Escribe tu comentario…',
    maxlength: String(Comments.MAX),
    rows: '3',
    'aria-label': 'Comentario'
  });

  var msg = el('p', {
    class: 'msg',
    role: 'alert',
    hidden: ''
  });

  var btn = el('button', {
    type: 'button',
    class: 'btn',
    text: 'Comentar'
  });

  btn.addEventListener('click', function () {
    var text = ta.value.trim();

    if (!text) {
      msg.className = 'msg msg-error';
      msg.textContent = 'El comentario está vacío. Escribe algo antes de enviarlo.';
      msg.removeAttribute('hidden');
      return;
    }

    if (!Comments.add(songId, user, text)) {
      msg.className = 'msg msg-error';
      msg.textContent = 'No se pudo guardar el comentario (almacenamiento lleno).';
      msg.removeAttribute('hidden');
      return;
    }

    ta.value = '';
    msg.setAttribute('hidden', '');
    refresh();
  });

  det.appendChild(el('div', {
    class: 'comment-form'
  }, [ta, btn, msg]));

  return det;
}

/* ---------- Panel lateral con perfil, navegación y sesión ---------- */
function mountUserPanel(active) {
  var user = Auth.current();

  var panel = el('div', { class: 'user-panel' });

  var pfp = el('img', {
    id: 'pfp-display',
    alt: 'Foto de perfil',
    src: Profile.get(user)
  });

  var cont = el('div', { class: 'profile-container' });

  if (user) {
    var input = el('input', {
      type: 'file',
      id: 'pfp-input',
      accept: 'image/*'
    });

    var label = el('label', {
      for: 'pfp-input',
      title: 'Cambiar foto de perfil'
    }, [pfp]);

    cont.appendChild(label);
    cont.appendChild(input);

    input.addEventListener('change', function () {
      var file = this.files[0];

      if (!file) return;

      Profile.set(user, file, function (err) {
        if (err) {
          alert(err);
          input.value = '';
        } else {
          pfp.src = Profile.get(user);
        }
      });
    });
  } else {
    pfp.style.cursor = 'pointer';
    pfp.title = 'Inicia sesión para personalizar tu perfil';

    pfp.addEventListener('click', function () {
      promptLogin('personalizar tu foto de perfil');
    });

    cont.appendChild(pfp);
  }

  panel.appendChild(cont);

  panel.appendChild(el('span', {
    class: 'panel-user',
    text: user || 'Visitante'
  }));

  var nav = el('nav', { class: 'panel-nav' });

  [
    ['top10.html', '🏆 Top 10', false],
    ['subir.html', '⬆ Subir canción', true],
    ['explorar.html', '🔍 Explorar', true]
  ].forEach(function (l) {
    var a = el('a', {
      href: l[0],
      text: l[1],
      class: (active === l[0] ? 'active' : '')
    });

    if (l[2]) {
      a.addEventListener('click', function (e) {
        if (!Auth.current()) {
          e.preventDefault();
          promptLogin('acceder a esta función');
        }
      });
    }

    nav.appendChild(a);
  });

  panel.appendChild(nav);

  if (user) {
    var out = el('button', {
      class: 'btn-logout',
      type: 'button',
      text: 'Cerrar sesión'
    });

    out.addEventListener('click', function () {
      Auth.logout();
      window.location.href = 'index.html';
    });

    panel.appendChild(out);
  } else {
    var inn = el('button', {
      class: 'btn-login',
      type: 'button',
      text: 'Iniciar sesión'
    });

    inn.addEventListener('click', function () {
      window.location.href = 'index.html';
    });

    var reg = el('button', {
      class: 'btn-login',
      type: 'button',
      text: 'Registrarse'
    });

    reg.addEventListener('click', function () {
      window.location.href = 'registro.html';
    });

    panel.appendChild(inn);
    panel.appendChild(reg);
  }

  document.body.insertBefore(panel, document.body.firstChild);
}

/* ---------- Redirigir al inicio de sesión ---------- */
function promptLogin(action) {
  if (confirm(
    'Debes iniciar sesión para ' + action +
    '.\n\n¿Ir a la página de inicio de sesión?'
  )) {
    window.location.href = 'index.html';
  }
}