// ============================================
// Macless Haystack - Web Application
// FindMy/AirTag Tracker with secp224r1 Decryption
// Uses @noble/curves for elliptic curve cryptography
// ============================================

// App State
const state = {
    accessories: [],
    locations: [],
    settings: {
        endpointUrl: 'http://localhost:6176',
        endpointUser: '',
        endpointPass: '',
        daysToFetch: 7,
        fetchOnStartup: true,
        darkMode: false
    },
    map: null,
    markers: [],
    currentAccessoryId: null,
    selectedColor: '#3B82F6',
    selectedIcon: 'tag'
};

// Icon mapping
const iconMap = {
    tag: '🏷️',
    key: '🔑',
    bag: '🎒',
    bike: '🚲',
    car: '🚗',
    pet: '🐕'
};

// ============================================
// UTILITY FUNCTIONS
// ============================================

// Convert base64 to Uint8Array
function base64ToBytes(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

// Convert Uint8Array to base64
function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// Convert hex string to Uint8Array
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

// Convert Uint8Array to hex string
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// SHA-256 hash (using @noble/hashes via module import)
// The sha256 function is imported from @noble/hashes and available as window.nobleSha256
async function sha256(data) {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);

    // Try Web Crypto API first (requires secure context: HTTPS or localhost)
    if (window.crypto && window.crypto.subtle) {
        const buffer = await window.crypto.subtle.digest('SHA-256', bytes);
        return new Uint8Array(buffer);
    }

    // Fallback: use @noble/hashes sha256 (loaded via module)
    if (window.nobleSha256) {
        return window.nobleSha256(bytes);
    }

    throw new Error('No SHA-256 implementation available. Use localhost or HTTPS.');
}

// ============================================
// CRYPTOGRAPHY FUNCTIONS (secp224r1)
// ============================================

// Wait for noble-curves to be loaded
function waitForNobleCurves() {
    return new Promise((resolve) => {
        if (window.secp224r1 && window.nobleGcm) {
            resolve();
        } else {
            const checkInterval = setInterval(() => {
                if (window.secp224r1 && window.nobleGcm) {
                    clearInterval(checkInterval);
                    resolve();
                }
            }, 100);
        }
    });
}

// Initialize crypto
async function initCrypto() {
    await waitForNobleCurves();
    console.log('secp224r1 curve loaded:', window.secp224r1);
    console.log('nobleGcm loaded:', window.nobleGcm);
}

// Hash public key using SHA256 and encode as base64
// This computes the hashed advertisement key
async function hashPublicKey(privateKeyBase64) {
    // First, derive public key from private key
    const privateKeyBytes = base64ToBytes(privateKeyBase64);
    const publicKeyBytes = await derivePublicKeyFromPrivate(privateKeyBytes);

    // SHA-256 hash of the public key
    const hash = await sha256(publicKeyBytes);

    // Return base64 encoded hash
    return bytesToBase64(hash);
}

// Derive public key from private key using secp224r1
async function derivePublicKeyFromPrivate(privateKeyBytes) {
    if (!window.secp224r1) {
        throw new Error('secp224r1 curve not loaded');
    }

    // Convert bytes to hex for noble-curves
    const privHex = bytesToHex(privateKeyBytes);

    // Get public key from secp224r1
    const pubBytes = window.secp224r1.getPublicKey(privHex);

    return pubBytes;
}

// Get advertisement key (28-byte public key without first byte)
async function getAdvertisementKey(privateKeyBase64) {
    const publicKeyBytes = await derivePublicKeyFromPrivate(base64ToBytes(privateKeyBase64));

    // Drop first byte (compression flag) to get 28-byte advertisement key
    return publicKeyBytes.slice(1);
}

// Get hashed advertisement key (what the backend uses to lookup reports)
async function getHashedAdvertisementKey(privateKeyBase64) {
    const advKey = await getAdvertisementKey(privateKeyBase64);
    const hash = await sha256(advKey);
    return bytesToBase64(hash);
}

// ECDH - Elliptic Curve Diffie-Hellman key exchange
async function ecdh(ephemeralPublicKeyBytes, privateKeyBase64) {
    if (!window.secp224r1) {
        throw new Error('secp224r1 curve not loaded');
    }

    const privateKeyBytes = base64ToBytes(privateKeyBase64);
    const privHex = bytesToHex(privateKeyBytes);
    const pubHex = bytesToHex(ephemeralPublicKeyBytes);

    // Get shared secret using ECDH
    const shared = window.secp224r1.getSharedSecret(privHex, pubHex);

    // Remove first byte (parity byte) to get 28-byte X coordinate
    return shared.slice(1);
}

// KDF - ANSI X.963 Key Derivation Function
async function kdf(secret, ephemeralKey) {
    // SHA-256(secret || counter || ephemeralKey)
    // counter = 1 (4 bytes, big endian)

    const combined = new Uint8Array(secret.length + 4 + ephemeralKey.length);
    combined.set(secret, 0);
    combined.set(new Uint8Array([0, 0, 0, 1]), secret.length); // counter = 1
    combined.set(ephemeralKey, secret.length + 4);

    return sha256(combined);
}

// AES-GCM Decryption using Web Crypto API or noble/ciphers fallback
async function decryptPayload(cipherText, symmetricKey, tag) {
    // Split symmetric key: first 16 bytes for decryption key, rest for IV
    const decryptionKey = symmetricKey.slice(0, 16);
    const iv = symmetricKey.slice(16);

    // Try Web Crypto API first (requires secure context: HTTPS or localhost)
    if (window.crypto && window.crypto.subtle) {
        try {
            const cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                decryptionKey,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            // Combine cipher text and tag for GCM decryption
            const dataToDecrypt = new Uint8Array(cipherText.length + tag.length);
            dataToDecrypt.set(cipherText);
            dataToDecrypt.set(tag, cipherText.length);

            // Decrypt
            const decrypted = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                cryptoKey,
                dataToDecrypt
            );

            return new Uint8Array(decrypted);
        } catch (e) {
            console.warn('[WARN] Web Crypto API failed, trying fallback:', e);
        }
    }

    // Fallback: Use noble/ciphers gcm (works in non-secure contexts)
    if (window.nobleGcm) {
        try {
            // noble/ciphers GCM expects ciphertext || tag
            const combined = new Uint8Array(cipherText.length + tag.length);
            combined.set(cipherText);
            combined.set(tag, cipherText.length);

            console.log('[DEBUG] noble/ciphers decrypt, keyLen:', decryptionKey.length, 'ivLen:', iv.length, 'dataLen:', combined.length);

            // Create cipher with GCM mode
            const cipher = window.nobleGcm(decryptionKey, iv);
            const decrypted = cipher.decrypt(combined);

            console.log('[DEBUG] Decrypted length:', decrypted.length);
            return decrypted;
        } catch (e) {
            console.error('[ERROR] noble/ciphers decryption failed:', e);
        }
    }

    throw new Error('No AES-GCM decryption available. Access via localhost or HTTPS.');
}

// Main decryption function - decrypts a FindMy report
async function decryptReport(report, privateKeyBase64) {
    try {
        // Decode the payload
        let payloadData = base64ToBytes(report.payload);

        // Handle 89-byte payload (remove one byte for alignment)
        if (payloadData.length > 88) {
            const modified = new Uint8Array(payloadData.length - 1);
            modified.set(payloadData.slice(0, 4), 0);
            modified.set(payloadData.slice(5), 4);
            payloadData = modified;
        }

        // Parse payload structure:
        // [0-4]: timestamp (big-endian uint32)
        // [4]: confidence (uint8)
        // [5-62]: ephemeral public key (57 bytes, compressed format)
        // [62-72]: encrypted data (10 bytes)
        // [72-88]: authentication tag (16 bytes)
        const ephemeralKeyBytes = payloadData.slice(5, 62);
        const encData = payloadData.slice(62, 72);
        const tag = payloadData.slice(72);

        // Decode timestamp and confidence (unencrypted portion)
        const seenTimeStamp = new DataView(payloadData.buffer).getUint32(0, false);
        const timestamp = new Date(Date.UTC(2001, 0, 1));
        timestamp.setSeconds(seenTimeStamp);
        const confidence = payloadData[4];

        // ECDH key exchange
        const sharedSecret = await ecdh(ephemeralKeyBytes, privateKeyBase64);

        // Key derivation (ANSI X.963)
        const derivedKey = await kdf(sharedSecret, ephemeralKeyBytes);

        // Decrypt payload using AES-GCM
        const decryptedPayload = await decryptPayload(encData, derivedKey, tag);

        // Decode decrypted payload to get location data
        return decodePayload(decryptedPayload, report.datePublished, timestamp, confidence);
    } catch (error) {
        console.error('Decrypt report error:', error);
        throw error;
    }
}

// Decode the decrypted payload to get location data
function decodePayload(payload, datePublished, timestamp, confidence) {
    const view = new DataView(payload.buffer);

    // Parse latitude and longitude (in units of 0.0000001 degrees)
    const latitudeRaw = view.getUint32(0, false);
    const longitudeRaw = view.getUint32(4, false);
    const accuracy = view.getUint8(8);
    const status = view.getUint8(9);

    // Convert to degrees
    let latitude = latitudeRaw / 10000000.0;
    let longitude = longitudeRaw / 10000000.0;

    // Handle overflow correction (from original Flutter code)
    const pointCorrection = 0xFFFFFFFF / 10000000;
    if (latitude > 90) latitude -= pointCorrection;
    if (latitude < -90) latitude += pointCorrection;
    if (longitude > 180) longitude -= pointCorrection;
    if (longitude < -180) longitude += pointCorrection;

    // Decode battery status
    let batteryStatus = null;
    if ((status & 0x20) !== 0 || status > 0) {
        const batteryLevel = (status >> 6) & 0x03;
        const batteryStatuses = ['ok', 'medium', 'low', 'critical'];
        batteryStatus = batteryStatuses[batteryLevel] || null;
    }

    return {
        latitude,
        longitude,
        accuracy,
        datePublished,
        timestamp,
        confidence,
        batteryStatus
    };
}

// ============================================
// API FUNCTIONS
// ============================================

// Fetch location reports from backend endpoint
async function fetchLocationReportsFromEndpoint(hashedKeys, daysToFetch) {
    const url = state.settings.endpointUrl;

    // Prepare headers
    const headers = {
        'Content-Type': 'application/json'
    };

    // Add basic auth if credentials provided
    if (state.settings.endpointUser || state.settings.endpointPass) {
        const credentials = btoa(`${state.settings.endpointUser}:${state.settings.endpointPass}`);
        headers['Authorization'] = `Basic ${credentials}`;
    }

    // Prepare request body
    const body = JSON.stringify({
        ids: hashedKeys,
        days: daysToFetch
    });

    console.log('[DEBUG] Fetching from:', url);
    console.log('[DEBUG] Request body:', body);
    console.log('[DEBUG] Headers:', headers);

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

        const response = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: body,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        console.log('[DEBUG] Response status:', response.status);

        if (response.status === 401) {
            throw new Error('Authentication failed. Check your username/password.');
        }

        if (response.status === 404) {
            throw new Error('Endpoint not found. Check your URL.');
        }

        if (response.status !== 200) {
            const errorText = await response.text();
            console.error('[DEBUG] Error response:', errorText);
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        console.log('[DEBUG] Response data:', data);
        console.log('[DEBUG] Results count:', data.results?.length || 0);

        return data.results || [];
    } catch (error) {
        console.error('[DEBUG] Fetch error:', error);
        if (error.name === 'AbortError') {
            throw new Error('Request timed out (30s). Check if endpoint is running.');
        }
        throw error;
    }
}

// ============================================
// INITIALIZATION
// ============================================

// Initialize App
document.addEventListener('DOMContentLoaded', async () => {
    await initCrypto();
    loadSettings();
    loadAccessories();
    initMap();
    initEventListeners();
    applyDarkMode();

    if (state.settings.fetchOnStartup) {
        fetchLocations();
    }
});

// Initialize Map
function initMap() {
    state.map = L.map('map').setView([0, 0], 2);

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(state.map);
}

// Initialize Event Listeners
function initEventListeners() {
    // Tab navigation
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Settings modal
    document.getElementById('settingsBtn').addEventListener('click', openSettingsModal);
    document.getElementById('closeSettingsBtn').addEventListener('click', closeSettingsModal);
    document.getElementById('saveSettingsBtn').addEventListener('click', saveSettings);
    document.getElementById('testConnectionBtn').addEventListener('click', testEndpointConnection);

    // Accessory modal
    document.getElementById('addAccessoryBtn').addEventListener('click', () => openAccessoryModal());
    document.getElementById('fabBtn').addEventListener('click', () => openAccessoryModal());
    document.getElementById('closeAccessoryBtn').addEventListener('click', closeAccessoryModal);
    document.getElementById('cancelAccessoryBtn').addEventListener('click', closeAccessoryModal);
    document.getElementById('saveAccessoryBtn').addEventListener('click', saveAccessory);

    // Device JSON import
    document.getElementById('importDeviceJsonBtn').addEventListener('click', () => {
        document.getElementById('deviceJsonInput').click();
    });

    document.getElementById('deviceJsonInput').addEventListener('change', importDeviceJson);

    // Color picker
    document.querySelectorAll('.color-btn').forEach(btn => {
        btn.addEventListener('click', () => selectColor(btn.dataset.color));
    });

    // Icon picker
    document.querySelectorAll('.icon-btn').forEach(btn => {
        btn.addEventListener('click', () => selectIcon(btn.dataset.icon));
    });

    // Refresh button
    document.getElementById('refreshBtn').addEventListener('click', fetchLocations);

    // Days filter change
    document.getElementById('daysFilter').addEventListener('change', fetchLocations);

    // Import/Export
    document.getElementById('importBtn').addEventListener('click', () => {
        document.getElementById('fileInput').click();
    });

    document.getElementById('fileInput').addEventListener('change', (e) => {
        importAccessories(e.target.files[0]);
    });

    document.getElementById('exportBtn').addEventListener('click', exportAccessories);

    // Dark mode toggle
    document.getElementById('darkMode').addEventListener('change', (e) => {
        state.settings.darkMode = e.target.checked;
        applyDarkMode();
        saveSettings();
    });

    // Close modals on outside click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });
}

// ============================================
// TAB SWITCHING
// ============================================

function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tabName}Tab`);
    });

    if (tabName === 'map') {
        setTimeout(() => state.map.invalidateSize(), 100);
    }
}

// ============================================
// SETTINGS
// ============================================

function loadSettings() {
    const saved = localStorage.getItem('haystackSettings');
    if (saved) {
        try {
            state.settings = { ...state.settings, ...JSON.parse(saved) };
        } catch (e) {
            console.error('Failed to load settings:', e);
        }
    }

    document.getElementById('endpointUrl').value = state.settings.endpointUrl;
    document.getElementById('endpointUser').value = state.settings.endpointUser;
    document.getElementById('endpointPass').value = state.settings.endpointPass;
    document.getElementById('daysToFetch').value = state.settings.daysToFetch;
    document.getElementById('fetchOnStartup').checked = state.settings.fetchOnStartup;
    document.getElementById('darkMode').checked = state.settings.darkMode;
}

function saveSettings() {
    state.settings.endpointUrl = document.getElementById('endpointUrl').value.trim();
    state.settings.endpointUser = document.getElementById('endpointUser').value.trim();
    state.settings.endpointPass = document.getElementById('endpointPass').value.trim();
    state.settings.daysToFetch = parseInt(document.getElementById('daysToFetch').value);
    state.settings.fetchOnStartup = document.getElementById('fetchOnStartup').checked;
    state.settings.darkMode = document.getElementById('darkMode').checked;

    // Validate endpoint URL
    if (state.settings.endpointUrl && !state.settings.endpointUrl.match(/^https?:\/\/.+/)) {
        showToast('Invalid endpoint URL. Must start with http:// or https://', 'error');
        return;
    }

    localStorage.setItem('haystackSettings', JSON.stringify(state.settings));
    closeSettingsModal();
    showToast('Settings saved', 'success');
}

function openSettingsModal() {
    document.getElementById('settingsModal').classList.add('active');
}

function closeSettingsModal() {
    document.getElementById('settingsModal').classList.remove('active');
}

function applyDarkMode() {
    if (state.settings.darkMode) {
        document.body.classList.add('dark-mode');
    } else {
        document.body.classList.remove('dark-mode');
    }
}

// Test endpoint connection
async function testEndpointConnection() {
    const url = document.getElementById('endpointUrl').value.trim();
    const testBtn = document.getElementById('testConnectionBtn');
    const originalText = testBtn.textContent;

    if (!url) {
        showToast('Please enter an endpoint URL', 'error');
        return;
    }

    testBtn.textContent = 'Testing...';
    testBtn.disabled = true;

    console.log('[TEST] Checking endpoint:', url);

    try {
        // First try a simple GET request to check if server is reachable
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: [], days: 1 }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        console.log('[TEST] Response status:', response.status);

        if (response.status === 404) {
            showToast('Server reachable but endpoint not found. URL may need a path like /getLocationReports', 'warning');
        } else if (response.status === 401) {
            showToast('Server reachable! Authentication required (this is expected if you set a username/password)', 'success');
        } else if (response.status === 200 || response.status === 400) {
            // 400 is OK - means server is responding, just no valid data
            showToast('Connection successful!', 'success');
        } else {
            const text = await response.text();
            console.log('[TEST] Response:', text);
            showToast(`Server responded with status ${response.status}`, 'success');
        }
    } catch (error) {
        console.error('[TEST] Connection error:', error);
        if (error.name === 'AbortError') {
            showToast('Connection timed out. Server may be down or wrong address.', 'error');
        } else if (error.message.includes('Failed to fetch')) {
            showToast('Cannot reach server. Check URL and CORS settings.', 'error');
        } else {
            showToast(`Error: ${error.message}`, 'error');
        }
    } finally {
        testBtn.textContent = originalText;
        testBtn.disabled = false;
    }
}

// ============================================
// ACCESSORIES
// ============================================

function loadAccessories() {
    const saved = localStorage.getItem('haystackAccessories');
    if (saved) {
        try {
            state.accessories = JSON.parse(saved);
        } catch (e) {
            console.error('Failed to load accessories:', e);
            state.accessories = [];
        }
    }
    renderAccessoriesList();
    renderAccessoriesGrid();
}

function saveAccessories() {
    localStorage.setItem('haystackAccessories', JSON.stringify(state.accessories));
    renderAccessoriesList();
    renderAccessoriesGrid();
}

function openAccessoryModal(accessoryId = null) {
    state.currentAccessoryId = accessoryId;
    state.selectedColor = '#3B82F6';
    state.selectedIcon = 'tag';

    if (accessoryId) {
        const accessory = state.accessories.find(a => a.id === accessoryId);
        if (accessory) {
            document.getElementById('accessoryModalTitle').textContent = 'Edit Accessory';
            document.getElementById('accessoryName').value = accessory.name;
            document.getElementById('accessoryId').value = accessory.deviceId;
            document.getElementById('accessoryKey').value = accessory.privateKey;
            state.selectedColor = accessory.color;
            state.selectedIcon = accessory.icon;
        }
    } else {
        document.getElementById('accessoryModalTitle').textContent = 'Add Accessory';
        document.getElementById('accessoryName').value = '';
        document.getElementById('accessoryId').value = '';
        document.getElementById('accessoryKey').value = '';
    }

    selectColor(state.selectedColor);
    selectIcon(state.selectedIcon);
    document.getElementById('accessoryModal').classList.add('active');
}

function closeAccessoryModal() {
    document.getElementById('accessoryModal').classList.remove('active');
    state.currentAccessoryId = null;
}

function selectColor(color) {
    state.selectedColor = color;
    let found = false;
    document.querySelectorAll('.color-btn').forEach(btn => {
        const isSelected = btn.dataset.color === color;
        btn.classList.toggle('selected', isSelected);
        if (isSelected) found = true;
    });

    // If color is not in the predefined list, select the first button visually
    // but keep the custom color in state
    if (!found) {
        document.querySelector('.color-btn')?.classList.add('selected');
    }
}

function selectIcon(icon) {
    state.selectedIcon = icon;
    document.querySelectorAll('.icon-btn').forEach(btn => {
        btn.classList.toggle('selected', btn.dataset.icon === icon);
    });
}

function saveAccessory() {
    const name = document.getElementById('accessoryName').value.trim();
    const deviceId = document.getElementById('accessoryId').value.trim();
    const privateKey = document.getElementById('accessoryKey').value.trim();

    if (!name || !deviceId || !privateKey) {
        showToast('Please fill in all fields', 'error');
        return;
    }

    const accessory = {
        id: state.currentAccessoryId || Date.now().toString(),
        name,
        deviceId,
        privateKey,
        color: state.selectedColor,
        icon: state.selectedIcon,
        active: true,
        createdAt: new Date().toISOString()
    };

    if (state.currentAccessoryId) {
        const index = state.accessories.findIndex(a => a.id === state.currentAccessoryId);
        if (index !== -1) {
            state.accessories[index] = accessory;
        }
    } else {
        state.accessories.push(accessory);
    }

    saveAccessories();
    closeAccessoryModal();
    showToast('Accessory saved', 'success');
}

function deleteAccessory(id) {
    if (confirm('Are you sure you want to delete this accessory?')) {
        state.accessories = state.accessories.filter(a => a.id !== id);
        saveAccessories();
        showToast('Accessory deleted', 'success');
    }
}

function renderAccessoriesList() {
    const container = document.getElementById('accessoriesList');

    if (state.accessories.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">📍</div>
                <div class="empty-state-text">No accessories yet</div>
                <div class="empty-state-subtext">Add your first accessory to start tracking</div>
            </div>
        `;
        return;
    }

    container.innerHTML = state.accessories.map(accessory => `
        <div class="accessory-item" onclick="focusOnAccessory('${accessory.id}')">
            <div class="accessory-header">
                <div class="accessory-icon" style="background: ${accessory.color}20; color: ${accessory.color}">
                    ${iconMap[accessory.icon] || '🏷️'}
                </div>
                <div class="accessory-info">
                    <div class="accessory-name">${accessory.name}</div>
                    <div class="accessory-meta">${accessory.deviceId}</div>
                </div>
                <div class="accessory-status ${accessory.active ? 'active' : 'inactive'}"></div>
            </div>
        </div>
    `).join('');
}

function renderAccessoriesGrid() {
    const container = document.getElementById('accessoriesGrid');

    if (state.accessories.length === 0) {
        container.innerHTML = `
            <div class="empty-state" style="grid-column: 1 / -1;">
                <div class="empty-state-icon">🎒</div>
                <div class="empty-state-text">No accessories yet</div>
                <div class="empty-state-subtext">Add your first accessory to start tracking</div>
            </div>
        `;
        return;
    }

    container.innerHTML = state.accessories.map(accessory => `
        <div class="accessory-card">
            <div class="accessory-card-header">
                <div class="accessory-card-icon" style="background: ${accessory.color}20; color: ${accessory.color}">
                    ${iconMap[accessory.icon] || '🏷️'}
                </div>
                <div class="accessory-info">
                    <div class="accessory-name">${accessory.name}</div>
                    <div class="accessory-meta">${accessory.deviceId}</div>
                    <div class="accessory-meta">
                        Status: <span style="color: ${accessory.active ? 'var(--success)' : 'var(--secondary)'}">${accessory.active ? 'Active' : 'Inactive'}</span>
                    </div>
                </div>
            </div>
            <div class="accessory-card-actions">
                <button class="secondary-btn" onclick="openAccessoryModal('${accessory.id}')">Edit</button>
                <button class="secondary-btn" onclick="deleteAccessory('${accessory.id}')" style="background: var(--danger)">Delete</button>
                <button class="secondary-btn" onclick="toggleActive('${accessory.id}')">${accessory.active ? 'Deactivate' : 'Activate'}</button>
            </div>
        </div>
    `).join('');
}

function toggleActive(id) {
    const accessory = state.accessories.find(a => a.id === id);
    if (accessory) {
        accessory.active = !accessory.active;
        saveAccessories();
        showToast(`Accessory ${accessory.active ? 'activated' : 'deactivated'}`, 'success');
    }
}

function focusOnAccessory(id) {
    const accessory = state.accessories.find(a => a.id === id);
    if (accessory && state.locations.length > 0) {
        const accessoryLocations = state.locations.filter(l => l.accessoryId === id);
        if (accessoryLocations.length > 0) {
            const latest = accessoryLocations[accessoryLocations.length - 1];
            state.map.setView([latest.lat, latest.lng], 15);
        }
    }
}

// ============================================
// LOCATION FETCHING
// ============================================

async function fetchLocations() {
    const refreshBtn = document.getElementById('refreshBtn');
    const days = parseInt(document.getElementById('daysFilter').value);
    const activeAccessories = state.accessories.filter(a => a.active);

    console.log('[DEBUG] Active accessories:', activeAccessories.map(a => ({ name: a.name, deviceId: a.deviceId })));

    if (activeAccessories.length === 0) {
        showToast('No active accessories to fetch', 'warning');
        return;
    }

    refreshBtn.classList.add('loading');
    refreshBtn.disabled = true;

    try {
        // Generate hashed keys for all active accessories
        const hashedKeys = [];
        console.log('[DEBUG] Generating hashed keys...');
        for (const accessory of activeAccessories) {
            const hashedKey = await getHashedAdvertisementKey(accessory.privateKey);
            hashedKeys.push(hashedKey);
            console.log(`[DEBUG] ${accessory.name} (${accessory.deviceId}) -> hashedKey: ${hashedKey}`);
        }

        console.log('[DEBUG] Total hashed keys:', hashedKeys.length);

        // Fetch reports from backend
        const reports = await fetchLocationReportsFromEndpoint(hashedKeys, days);

        // Decrypt each report
        const locations = [];
        for (const report of reports) {
            // Find matching accessory
            const accessory = activeAccessories.find(async (a) => {
                const hashedKey = await getHashedAdvertisementKey(a.privateKey);
                return hashedKey === report.id;
            });

            if (accessory) {
                try {
                    const decrypted = await decryptReport(report, accessory.privateKey);
                    locations.push({
                        accessoryId: accessory.id,
                        accessoryName: accessory.name,
                        lat: decrypted.latitude,
                        lng: decrypted.longitude,
                        timestamp: decrypted.timestamp.getTime(),
                        accuracy: decrypted.accuracy,
                        confidence: decrypted.confidence,
                        batteryStatus: decrypted.batteryStatus
                    });
                } catch (decryptError) {
                    console.error('Failed to decrypt report:', decryptError);
                }
            }
        }

        // Sort by timestamp
        locations.sort((a, b) => a.timestamp - b.timestamp);

        state.locations = locations;
        updateMapMarkers();
        showToast(`Fetched ${locations.length} location(s)`, 'success');

        if (locations.length === 0) {
            showToast('No locations found. Check your endpoint connection and keys.', 'warning');
        }
    } catch (error) {
        console.error('Error fetching locations:', error);
        showToast(`Failed to fetch: ${error.message}`, 'error');
    } finally {
        refreshBtn.classList.remove('loading');
        refreshBtn.disabled = false;
    }
}

function updateMapMarkers() {
    // Clear existing markers
    state.markers.forEach(marker => state.map.removeLayer(marker));
    state.markers = [];

    if (state.locations.length === 0) {
        return;
    }

    // Group locations by accessory
    const locationsByAccessory = {};
    state.locations.forEach(loc => {
        if (!locationsByAccessory[loc.accessoryId]) {
            locationsByAccessory[loc.accessoryId] = [];
        }
        locationsByAccessory[loc.accessoryId].push(loc);
    });

    // Add markers for each accessory
    Object.entries(locationsByAccessory).forEach(([accessoryId, locations]) => {
        const accessory = state.accessories.find(a => a.id === accessoryId);
        if (!accessory) return;

        const latest = locations[locations.length - 1];

        // Create custom icon
        const icon = L.divIcon({
            className: 'custom-marker',
            html: `<div style="background: ${accessory.color}; width: 32px; height: 32px; border-radius: 50%; display: flex; align-items: center; justify-content: center; border: 3px solid white; box-shadow: 0 2px 4px rgba(0,0,0,0.3);">${iconMap[accessory.icon] || '🏷️'}</div>`,
            iconSize: [32, 32],
            iconAnchor: [16, 16]
        });

        const popupContent = `
            <div class="custom-popup">
                <div class="custom-popup-icon">${iconMap[accessory.icon] || '🏷️'}</div>
                <div class="custom-popup-name">${accessory.name}</div>
                <div class="custom-popup-time">${new Date(latest.timestamp).toLocaleString()}</div>
                <div style="font-size: 0.75rem; margin-top: 0.25rem;">Accuracy: ±${latest.accuracy}m</div>
                ${latest.batteryStatus ? `<div style="font-size: 0.75rem;">Battery: ${latest.batteryStatus}</div>` : ''}
            </div>
        `;

        const marker = L.marker([latest.lat, latest.lng], { icon })
            .addTo(state.map)
            .bindPopup(popupContent);

        state.markers.push(marker);
    });

    // Fit map to show all markers
    if (state.markers.length > 0) {
        const group = new L.featureGroup(state.markers);
        state.map.fitBounds(group.getBounds().pad(0.1));
    }
}

// ============================================
// IMPORT/EXPORT
// ============================================

// Convert colorComponents [r, g, b, a] to hex color
function colorComponentsToHex(components) {
    // Handle both 0-1 range and 0-255 range
    const toHex = (val) => {
        // If value is between 0-1, convert to 0-255
        const num = val <= 1 ? Math.round(val * 255) : Math.round(val);
        return num.toString(16).padStart(2, '0');
    };

    if (components && components.length >= 3) {
        const r = toHex(components[0]);
        const g = toHex(components[1]);
        const b = toHex(components[2]);
        return `#${r}${g}${b}`.toUpperCase();
    }
    return '#3B82F6'; // Default blue
}

// Convert device id to hex string
function deviceIdToHex(id) {
    if (typeof id === 'number') {
        return id.toString(16).toUpperCase().padStart(8, '0');
    }
    return id.toString();
}

// Import device.json file and auto-fill the form
function importDeviceJson(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const data = JSON.parse(e.target.result);

            // Handle both array and single object
            const devices = Array.isArray(data) ? data : [data];

            if (devices.length === 0) {
                showToast('No devices found in file', 'error');
                return;
            }

            // Use the first device to populate the form
            const device = devices[0];

            // Fill in the form fields
            document.getElementById('accessoryName').value = device.name || '';
            document.getElementById('accessoryId').value = deviceIdToHex(device.id);
            document.getElementById('accessoryKey').value = device.privateKey || '';

            // Set color from colorComponents
            const hexColor = colorComponentsToHex(device.colorComponents);
            selectColor(hexColor);

            // Set icon - map from device.json icon or use default
            const iconMapping = {
                '': 'tag',
                'tag': 'tag',
                'key': 'key',
                'bag': 'bag',
                'backpack': 'bag',
                'bike': 'bike',
                'bicycle': 'bike',
                'car': 'car',
                'vehicle': 'car',
                'pet': 'pet',
                'dog': 'pet',
                'cat': 'pet'
            };
            const icon = iconMapping[device.icon] || 'tag';
            selectIcon(icon);

            // Store isActive status for when saving
            state.importedIsActive = device.isActive !== undefined ? device.isActive : true;

            showToast(`Loaded "${device.name}" from device.json`, 'success');

            // If there are multiple devices, offer to import all
            if (devices.length > 1) {
                setTimeout(() => {
                    if (confirm(`This file contains ${devices.length} devices. Import all of them?`)) {
                        importAllDevices(devices);
                    }
                }, 500);
            }
        } catch (error) {
            console.error('Import device.json error:', error);
            showToast('Failed to parse device.json file', 'error');
        }
    };
    reader.readAsText(file);

    // Reset file input so the same file can be selected again
    event.target.value = '';
}

// Import all devices from device.json array
async function importAllDevices(devices) {
    let imported = 0;

    for (const device of devices) {
        try {
            const accessory = {
                id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
                name: device.name || 'Unknown',
                deviceId: deviceIdToHex(device.id),
                privateKey: device.privateKey || '',
                color: colorComponentsToHex(device.colorComponents),
                icon: 'tag', // Default icon for bulk import
                active: device.isActive !== undefined ? device.isActive : true,
                createdAt: new Date().toISOString()
            };

            state.accessories.push(accessory);
            imported++;
        } catch (error) {
            console.error('Error importing device:', device, error);
        }
    }

    saveAccessories();
    showToast(`Imported ${imported} device(s)`, 'success');
    closeAccessoryModal();
}

function exportAccessories() {
    const exportData = state.accessories.map(a => ({
        name: a.name,
        deviceId: a.deviceId,
        privateKey: a.privateKey,
        color: a.color,
        icon: a.icon,
        active: a.active
    }));

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `accessories_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);

    showToast('Accessories exported', 'success');
}

function importAccessories(file) {
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const imported = JSON.parse(e.target.result);

            imported.forEach(item => {
                state.accessories.push({
                    id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
                    name: item.name,
                    deviceId: item.deviceId,
                    privateKey: item.privateKey,
                    color: item.color || '#3B82F6',
                    icon: item.icon || 'tag',
                    active: item.active !== undefined ? item.active : true,
                    createdAt: new Date().toISOString()
                });
            });

            saveAccessories();
            showToast(`Imported ${imported.length} accessory/ies`, 'success');
        } catch (error) {
            console.error('Import error:', error);
            showToast('Failed to import accessories', 'error');
        }
    };
    reader.readAsText(file);
}

// ============================================
// TOAST NOTIFICATION
// ============================================

function showToast(message, type = 'info') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;

    setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}
