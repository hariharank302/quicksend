(() => {
    const $ = (sel) => document.querySelector(sel);

    const els = {
        dropZone: $('#dropZone'),
        selectBtn: $('#selectBtn'),
        fileInput: $('#fileInput'),
        fileInfo: $('#fileInfo'),
        copyInput: $('#copylink'),
        copyBtn: document.querySelector('.copy-btn'),
        password: $('#password'),
        startBtn: $('#startBtn'),
        cancelBtn: $('#cancelBtn'),
        log: $('#log')
    };

    const state = {
        roomId: null,
        mode: 'idle', // 'sender' | 'receiver'
        file: null,
        ws: null,
        peer: null,
        sending: false,
        receiving: false,
        aborted: false,
        bytesSent: 0,
        bytesRecv: 0,
        meta: null,
        writer: null,
        recvChunks: [],
        recvChunkIndex: 0,
        enc: {
            enabled: false,
            key: null,
            salt: null,
            baseIV: null,
            iterations: 150000
        }
    };

    // Signaling URL: same origin at /ws (deploy a tiny server; see server.js below)
    const SIGNAL_URL = (() => {
        const proto = (location.protocol === 'https:') ? 'wss:' : 'ws:';
        return `${proto}//${location.host}/ws`;
    })();

    const CHUNK_SIZE = 64 * 1024; // 64 KiB default for DC
    const ICE_SERVERS = [
        { urls: ['stun:stun.l.google.com:19302'] } // add TURN in production
    ];

    // Utilities
    const log = (msg) => { els.log.textContent = msg; };
    const setInfo = (msg) => { els.fileInfo.textContent = msg; };
    const fmtBytes = (n) => {
        if (n < 1024) return `${n} B`;
        const k = 1024;
        const units = ['KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(n) / Math.log(k));
        return `${(n / Math.pow(k, i + 1)).toFixed(2)} ${units[i]}`;
    };
    const randomId = (len = 22) => {
        const bytes = new Uint8Array(len);
        crypto.getRandomValues(bytes);
        return btoa(String.fromCharCode(...bytes))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    };
    const getRoomFromURL = () => new URL(location.href).searchParams.get('room');
    const withRoomLink = (room) => {
        const u = new URL(location.href);
        u.searchParams.set('room', room);
        u.hash = '';
        return u.toString();
    };

    // Password-based crypto helpers (AES-GCM per chunk)
    async function deriveKey(password, salt, iterations) {
        const enc = new TextEncoder();
        const keyMat = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
            keyMat,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }
    function incIV(baseIV, counter) {
        const iv = new Uint8Array(baseIV); // copy
        const view = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
        const last = view.getUint32(8, false);
        view.setUint32(8, (last + counter) >>> 0, false);
        return iv;
    }

    // File selection & drop
    function wireFilePickers() {
        els.selectBtn.addEventListener('click', () => els.fileInput.click());
        els.fileInput.addEventListener('change', () => {
            const f = els.fileInput.files?.[0] || null;
            if (f) {
                state.file = f;
                setInfo(`${f.name} • ${fmtBytes(f.size)} • ${f.type || 'application/octet-stream'}`);
            }
        });
        ['dragenter', 'dragover'].forEach(ev => {
            els.dropZone.addEventListener(ev, (e) => {
                e.preventDefault(); e.stopPropagation();
                els.dropZone.classList.add('is-dragover');
            });
        });
        ['dragleave', 'drop'].forEach(ev => {
            els.dropZone.addEventListener(ev, (e) => {
                e.preventDefault(); e.stopPropagation();
                if (ev === 'drop') {
                    const f = e.dataTransfer?.files?.[0] || null;
                    if (f) {
                        state.file = f;
                        setInfo(`${f.name} • ${fmtBytes(f.size)} • ${f.type || 'application/octet-stream'}`);
                    }
                }
                els.dropZone.classList.remove('is-dragover');
            });
        });
    }

    // Clipboard copy
    function wireCopy() {
        els.copyBtn.addEventListener('click', async () => {
            const val = els.copyInput.value.trim();
            if (!val) return;
            try {
                await navigator.clipboard.writeText(val);
                log('Link copied to clipboard.');
            } catch {
                els.copyInput.select();
                document.execCommand('copy');
                log('Link copied.');
            }
        });
    }

    // Start / Cancel
    function wireActions() {
        els.startBtn.addEventListener('click', async () => {
            if (state.mode === 'receiver') {
                connectReceiver();
            } else {
                if (!state.file) { log('Select a file first.'); return; }
                await startSender();
            }
        });

        els.cancelBtn.addEventListener('click', () => {
            state.aborted = true;
            if (state.peer) { try { state.peer.destroy(); } catch { } state.peer = null; }
            if (state.ws) { try { state.ws.close(); } catch { } state.ws = null; }
            state.sending = false;
            state.receiving = false;
            state.bytesSent = 0;
            state.bytesRecv = 0;
            state.writer = null;
            state.recvChunks = [];
            state.recvChunkIndex = 0;
            log('Transfer cancelled.');
            setInfo('');
        });
    }

    // Init mode from URL
    function initMode() {
        const room = getRoomFromURL();
        if (room) {
            state.roomId = room;
            state.mode = 'receiver';
            els.startBtn.textContent = 'Connect';
            log('Receiver mode: click Connect to begin.');
        } else {
            state.mode = 'sender';
            log('Sender mode: select a file and click Start.');
        }
    }

    // Signaling
    function openSignal(room) {
        return new Promise((resolve, reject) => {
            const ws = new WebSocket(SIGNAL_URL);
            state.ws = ws;
            ws.onopen = () => {
                ws.send(JSON.stringify({ t: 'join', room }));
                resolve(ws);
            };
            ws.onerror = () => reject(new Error('Signaling error.'));
        });
    }
    function sendSignal(payload) {
        if (state.ws && state.ws.readyState === 1) {
            state.ws.send(JSON.stringify(payload));
        }
    }

    // Simple-Peer setup
    function createPeer(initiator) {
        const p = new SimplePeer({
            initiator,
            trickle: true,
            config: { iceServers: ICE_SERVERS }
        });
        p.on('signal', (data) => {
            sendSignal({ t: 'signal', room: state.roomId, data });
        });
        p.on('connect', () => {
            if (state.mode === 'sender') {
                void sendFile();
            } else {
                log('Connected. Waiting for file metadata...');
            }
        });
        p.on('data', (data) => {
            if (typeof data === 'string') {
                handleControl(JSON.parse(data));
            } else {
                void handleChunk(data);
            }
        });
        p.on('drain', () => { });
        p.on('close', () => {
            if (!state.aborted) log('Peer disconnected.');
        });
        p.on('error', (err) => {
            log(`Peer error: ${err?.message || err}`);
        });
        return p;
    }

    // Control messages: meta, end, error
    async function handleControl(msg) {
        if (msg.type === 'meta') {
            state.receiving = true;
            state.meta = msg;
            state.bytesRecv = 0;
            if (msg.enc) {
                const pwd = els.password.value.trim();
                if (!pwd) { log('Password required. Enter it and click Cancel, then Connect again.'); return; }
                state.enc.enabled = true;
                state.enc.salt = base64ToBytes(msg.salt);
                state.enc.baseIV = base64ToBytes(msg.baseIV);
                state.enc.iterations = msg.iterations || state.enc.iterations;
                try {
                    state.enc.key = await deriveKey(pwd, state.enc.salt, state.enc.iterations);
                } catch {
                    log('Failed to derive key. Check password.');
                    return;
                }
            } else {
                state.enc.enabled = false;
            }
            if ('showSaveFilePicker' in window) {
                try {
                    const handle = await window.showSaveFilePicker({
                        suggestedName: msg.name || 'download'
                    });
                    state.writer = await handle.createWritable();
                    log(`Receiving: ${msg.name} • ${fmtBytes(msg.size)}`);
                } catch {
                    log('Save dialog was cancelled.');
                }
            } else {
                state.recvChunks = [];
                log(`Receiving (memory fallback): ${msg.name} • ${fmtBytes(msg.size)}`);
            }
        } else if (msg.type === 'end') {
            await finishReceive();
        } else if (msg.type === 'error') {
            log(`Remote error: ${msg.message || 'Unknown error'}`);
        }
    }

    async function handleChunk(chunk) {
        if (!state.receiving || !state.meta) return;
        let data = chunk;
        if (state.enc.enabled) {
            const iv = incIV(state.enc.baseIV, state.recvChunkIndex);
            try {
                data = new Uint8Array(await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv },
                    state.enc.key,
                    chunk
                ));
            } catch {
                log('Decryption failed. Wrong password or corrupted data.');
                return;
            }
            state.recvChunkIndex++;
        }
        state.bytesRecv += data.byteLength;

        if (state.writer) {
            await state.writer.write(data);
        } else {
            state.recvChunks.push(new Blob([data]));
        }

        const pct = Math.min(100, Math.floor((state.bytesRecv / state.meta.size) * 100));
        setInfo(`Receiving ${pct}% • ${fmtBytes(state.bytesRecv)} / ${fmtBytes(state.meta.size)}`);
    }

    async function finishReceive() {
        if (state.writer) {
            await state.writer.close();
            log('Download complete.');
            setInfo(`${state.meta.name} • ${fmtBytes(state.meta.size)} • saved`);
        } else {
            const blob = new Blob(state.recvChunks, { type: state.meta.type || 'application/octet-stream' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = state.meta.name || 'download';
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(a.href);
            log('Download complete.');
            setInfo(`${state.meta.name} • ${fmtBytes(state.meta.size)}`);
        }
        state.receiving = false;
    }

    // Sender flow
    async function startSender() {
        state.roomId = randomId();
        els.copyInput.value = withRoomLink(state.roomId);
        log('Share the link. Waiting for receiver to connect...');
        await openSignal(state.roomId);

        state.peer = createPeer(true);
        state.ws.onmessage = (ev) => {
            try {
                const msg = JSON.parse(ev.data);
                if (msg.t === 'signal' && msg.room === state.roomId && msg.data) {
                    state.peer.signal(msg.data);
                }
            } catch { }
        };

        const pwd = els.password.value.trim();
        if (pwd) {
            state.enc.enabled = true;
            state.enc.salt = crypto.getRandomValues(new Uint8Array(16));
            state.enc.baseIV = crypto.getRandomValues(new Uint8Array(12));
            try {
                state.enc.key = await deriveKey(pwd, state.enc.salt, state.enc.iterations);
            } catch {
                log('Failed to derive key from password.');
                state.enc.enabled = false;
            }
        } else {
            state.enc.enabled = false;
        }
    }

    async function sendFile() {
        if (!state.file) { log('No file selected.'); return; }
        state.sending = true;
        state.bytesSent = 0;

        const meta = {
            type: 'meta',
            name: state.file.name,
            size: state.file.size,
            mime: state.file.type || 'application/octet-stream',
            enc: state.enc.enabled,
            salt: state.enc.enabled ? bytesToBase64(state.enc.salt) : null,
            baseIV: state.enc.enabled ? bytesToBase64(state.enc.baseIV) : null,
            iterations: state.enc.iterations,
            chunkSize: CHUNK_SIZE
        };
        state.peer.send(JSON.stringify(meta));

        const reader = state.file.stream().getReader();
        let index = 0;

        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done || state.aborted) break;
                const buf = value instanceof Uint8Array ? value : new Uint8Array(value);
                for (let offset = 0; offset < buf.byteLength; offset += CHUNK_SIZE) {
                    if (state.aborted) break;
                    const slice = buf.subarray(offset, Math.min(offset + CHUNK_SIZE, buf.byteLength));
                    let toSend = slice;
                    if (state.enc.enabled) {
                        const iv = incIV(state.enc.baseIV, index++);
                        const encBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.enc.key, slice);
                        toSend = new Uint8Array(encBuf);
                    }
                    const ok = state.peer.send(toSend);
                    if (!ok) await onceDrain(state.peer);
                    state.bytesSent += slice.byteLength;
                    const pct = Math.min(100, Math.floor((state.bytesSent / state.file.size) * 100));
                    setInfo(`Sending ${pct}% • ${fmtBytes(state.bytesSent)} / ${fmtBytes(state.file.size)}`);
                }
            }
            state.peer.send(JSON.stringify({ type: 'end' }));
            log('Send complete.');
        } catch (err) {
            try { state.peer.send(JSON.stringify({ type: 'error', message: 'Sender error' })); } catch { }
            log(`Send error: ${err?.message || err}`);
        } finally {
            state.sending = false;
        }
    }

    function onceDrain(peer) {
        return new Promise((resolve) => {
            const onDrain = () => { peer.off('drain', onDrain); resolve(); };
            peer.on('drain', onDrain);
        });
    }

    async function connectReceiver() {
        if (!state.roomId) { log('Invalid room.'); return; }
        await openSignal(state.roomId);
        state.peer = createPeer(false);
        state.ws.onmessage = (ev) => {
            try {
                const msg = JSON.parse(ev.data);
                if (msg.t === 'signal' && msg.room === state.roomId && msg.data) {
                    state.peer.signal(msg.data);
                }
            } catch { }
        };
        log('Connecting to sender...');
    }

    // Base64 helpers
    function bytesToBase64(bytes) {
        let s = '';
        for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
        return btoa(s);
    }
    function base64ToBytes(b64) {
        const s = atob(b64);
        const out = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
        return out;
    }

    // Boot
    wireFilePickers();
    wireCopy();
    wireActions();
    initMode();
})();
