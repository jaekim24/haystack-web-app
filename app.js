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
    pathPolylines: [],
    currentAccessoryId: null,
    selectedColor: '#3B82F6',
    selectedIcon: 'tag',
    selectedDeviceId: null
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
async function hashPublicKey(privateKeyBase64) {
    const privateKeyBytes = base64ToBytes(privateKeyBase64);
    const publicKeyBytes = await derivePublicKeyFromPrivate(privateKeyBytes);
    const hash = await sha256(publicKeyBytes);
    return bytesToBase64(hash);
}

// Derive public key from private key using secp224r1
async function derivePublicKeyFromPrivate(privateKeyBytes) {
    if (!window.secp224r1) {
        throw new Error('secp224r1 curve not loaded');
    }

    const privHex = bytesToHex(privateKeyBytes);
    const pubBytes = window.secp224r1.getPublicKey(privHex);
    return pubBytes;
}

// Get advertisement key (28-byte public key without first byte)
async function getAdvertisementKey(privateKeyBase64) {
    const publicKeyBytes = await derivePublicKeyFromPrivate(base64ToBytes(privateKeyBase64));
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

    const shared = window.secp224r1.getSharedSecret(privHex, pubHex);
    return shared.slice(1);
}

// KDF - ANSI X.963 Key Derivation Function
async function kdf(secret, ephemeralKey) {
    const combined = new Uint8Array(secret.length + 4 + ephemeralKey.length);
    combined.set(secret, 0);
    combined.set(new Uint8Array([0, 0, 0, 1]), secret.length);
    combined.set(ephemeralKey, secret.length + 4);

    return sha256(combined);
}

// AES-GCM Decryption using Web Crypto API or noble/ciphers fallback
async function decryptPayload(cipherText, symmetricKey, tag) {
    const decryptionKey = symmetricKey.slice(0, 16);
    const iv = symmetricKey.slice(16);

    if (window.crypto && window.crypto.subtle) {
        try {
            const cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                decryptionKey,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );

            const dataToDecrypt = new Uint8Array(cipherText.length + tag.length);
            dataToDecrypt.set(cipherText);
            dataToDecrypt.set(tag, cipherText.length);

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

    if (window.nobleGcm) {
        try {
            const combined = new Uint8Array(cipherText.length + tag.length);
            combined.set(cipherText);
            combined.set(tag, cipherText.length);

            const cipher = window.nobleGcm(decryptionKey, iv);
            const decrypted = cipher.decrypt(combined);

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
        let payloadData = base64ToBytes(report.payload);

        if (payloadData.length > 88) {
            const modified = new Uint8Array(payloadData.length - 1);
            modified.set(payloadData.slice(0, 4), 0);
            modified.set(payloadData.slice(5), 4);
            payloadData = modified;
        }

        const ephemeralKeyBytes = payloadData.slice(5, 62);
        const encData = payloadData.slice(62, 72);
        const tag = payloadData.slice(72);

        const seenTimeStamp = new DataView(payloadData.buffer).getUint32(0, false);
        const timestamp = new Date(Date.UTC(2001, 0, 1));
        timestamp.setSeconds(seenTimeStamp);
        const confidence = payloadData[4];

        const sharedSecret = await ecdh(ephemeralKeyBytes, privateKeyBase64);
        const derivedKey = await kdf(sharedSecret, ephemeralKeyBytes);
        const decryptedPayload = await decryptPayload(encData, derivedKey, tag);

        return decodePayload(decryptedPayload, report.datePublished, timestamp, confidence);
    } catch (error) {
        console.error('Decrypt report error:', error);
        throw error;
    }
}

// Decode the decrypted payload to get location data
function decodePayload(payload, datePublished, timestamp, confidence) {
    const view = new DataView(payload.buffer);

    const latitudeRaw = view.getUint32(0, false);
    const longitudeRaw = view.getUint32(4, false);
    const accuracy = view.getUint8(8);
    const status = view.getUint8(9);

    let latitude = latitudeRaw / 10000000.0;
    let longitude = longitudeRaw / 10000000.0;

    const pointCorrection = 0xFFFFFFFF / 10000000;
    if (latitude > 90) latitude -= pointCorrection;
    if (latitude < -90) latitude += pointCorrection;
    if (longitude > 180) longitude -= pointCorrection;
    if (longitude < -180) longitude += pointCorrection;

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

async function fetchLocationReportsFromEndpoint(hashedKeys, daysToFetch) {
    const url = state.settings.endpointUrl;

    const headers = {
        'Content-Type': 'application/json'
    };

    if (state.settings.endpointUser || state.settings.endpointPass) {
        const credentials = btoa(`${state.settings.endpointUser}:${state.settings.endpointPass}`);
        headers['Authorization'] = `Basic ${credentials}`;
    }

    const body = JSON.stringify({
        ids: hashedKeys,
        days: daysToFetch
    });

    console.log('[DEBUG] Fetching from:', url);
    console.log('[DEBUG] Request body:', body);

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000);

        const response = await fetch(url, {
            method: 'POST',
            headers: headers,
            body: body,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 401) {
            throw new Error('Authentication failed. Check your username/password.');
        }

        if (response.status === 404) {
            throw new Error('Endpoint not found. Check your URL.');
        }

        if (response.status !== 200) {
            const errorText = await response.text();
            throw new Error(`HTTP ${response.status}: ${errorText}`);
        }

        const data = await response.json();
        return data.results || [];
    } catch (error) {
        if (error.name === 'AbortError') {
            throw new Error('Request timed out (30s). Check if endpoint is running.');
        }
        throw error;
    }
}

// ============================================
// INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', async () => {
    await initCrypto();
    loadSettings();
    loadAccessories();
    initMap();
    initEventListeners();
    applyDarkMode();

    // Set default state: map view with devices panel hidden
    const panel = document.getElementById('bottomPanel');
    panel.classList.add('hidden');

    if (state.settings.fetchOnStartup) {
        fetchLocations();
    }
});

// Initialize Map
function initMap() {
    state.map = L.map('map', {
        zoomControl: false
    }).setView([0, 0], 2);

    // Satellite layer (Esri World Imagery) - base layer
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
        attribution: '',
        maxZoom: 19
    }).addTo(state.map);

    // Hybrid overlay - Reference overlay with labels and roads
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}', {
        attribution: '',
        maxZoom: 19
    }).addTo(state.map);

    // Roads overlay for hybrid view
    L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Transportation/MapServer/tile/{z}/{y}/{x}', {
        attribution: '',
        maxZoom: 19
    }).addTo(state.map);
}

// ============================================
// PANEL DRAG/SWIPE FUNCTIONALITY
// ============================================

function initPanelDrag() {
    const panel = document.getElementById('bottomPanel');
    const handle = document.getElementById('panelHandle');
    const devicesList = document.getElementById('devicesList');

    let startY = 0;
    let currentY = 0;
    let isDragging = false;
    let panelHeight = 0;
    let isExpanded = false;

    const collapsedHeight = 180;
    const expandedHeight = window.innerHeight * 0.65;

    // Store state on panel element for cross-function access
    panel._isExpanded = () => isExpanded;
    panel._setExpanded = (val) => { isExpanded = val; };

    function onStart(e) {
        // If touching the devices list and it's scrollable, don't start panel drag
        if (e.target.closest('#devicesList') && isExpanded) {
            const list = e.target.closest('#devicesList');
            // Allow scrolling if list is scrollable
            if (list.scrollHeight > list.clientHeight) {
                return;
            }
        }

        isDragging = true;
        startY = e.type.includes('mouse') ? e.clientY : e.touches[0].clientY;
        panelHeight = panel.offsetHeight;
        panel.classList.add('dragging');
    }

    function onMove(e) {
        if (!isDragging) return;

        currentY = e.type.includes('mouse') ? e.clientY : e.touches[0].clientY;
        const diff = startY - currentY;

        // Calculate new height
        let newHeight = isExpanded ? expandedHeight + diff : collapsedHeight + diff;

        // Constrain height
        newHeight = Math.max(150, Math.min(expandedHeight, newHeight));
        panel.style.height = newHeight + 'px';
    }

    function onEnd(e) {
        if (!isDragging) return;
        isDragging = false;
        panel.classList.remove('dragging');

        const currentHeight = panel.offsetHeight;
        const middleThreshold = (collapsedHeight + expandedHeight) / 2;

        // Snap to expanded or collapsed based on current position
        if (currentHeight > middleThreshold) {
            panel.classList.add('expanded');
            panel.style.height = '';
            isExpanded = true;
        } else {
            panel.classList.remove('expanded');
            panel.style.height = '';
            isExpanded = false;
        }
    }

    // Touch events - only on handle and panel (not on list)
    handle.addEventListener('touchstart', onStart, { passive: true });
    panel.addEventListener('touchstart', onStart, { passive: true });

    document.addEventListener('touchmove', onMove, { passive: true });
    document.addEventListener('touchend', onEnd);
    document.addEventListener('touchcancel', onEnd);

    // Mouse events (for desktop testing)
    handle.addEventListener('mousedown', onStart);
    panel.addEventListener('mousedown', onStart);
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onEnd);

    // Also allow clicking the handle to toggle
    handle.addEventListener('click', (e) => {
        if (!isDragging) {
            panel.classList.toggle('expanded');
            isExpanded = panel.classList.contains('expanded');
        }
    });

    // Update state when expanded class changes externally
    const observer = new MutationObserver(() => {
        isExpanded = panel.classList.contains('expanded');
    });
    observer.observe(panel, { attributes: true, attributeFilter: ['class'] });

    // Store expanded state for access by other functions
    state.panelExpanded = () => isExpanded;
    state.togglePanel = (forceState) => {
        if (forceState !== undefined) {
            isExpanded = forceState;
        }
        panel.classList.toggle('expanded', isExpanded);
    };
}

// Initialize Event Listeners
function initEventListeners() {
    // Bottom navigation
    document.getElementById('locationBtn').addEventListener('click', handleLocationBtn);
    document.getElementById('devicesBtn').addEventListener('click', handleDevicesBtn);
    document.getElementById('settingsBtn').addEventListener('click', openSettingsModal);

    // Panel swipe/drag functionality
    initPanelDrag();

    // Settings modal
    document.getElementById('closeSettingsBtn').addEventListener('click', closeSettingsModal);
    document.getElementById('saveSettingsBtn').addEventListener('click', saveSettings);
    document.getElementById('testConnectionBtn').addEventListener('click', testEndpointConnection);

    // Accessory modal
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

    // Device detail panel
    document.getElementById('showPathBtn').addEventListener('click', showDevicePath);
    document.getElementById('detailPanelHandle').addEventListener('click', closeDeviceDetail);

    // Swipe-right gesture on device detail panel
    initDetailPanelSwipe();

    // Add device button
    document.getElementById('addDeviceBtn').addEventListener('click', () => openAccessoryModal());

    // Refresh button
    document.getElementById('refreshBtn').addEventListener('click', handleRefresh);

    // Close modals on outside click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    });

    // Dark mode toggle
    document.getElementById('darkMode').addEventListener('change', (e) => {
        state.settings.darkMode = e.target.checked;
        applyDarkMode();
        saveSettings();
    });
}

// ============================================
// NAVIGATION HANDLERS
// ============================================

function handleLocationBtn() {
    // Update active state
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('nav-btn-active'));
    document.getElementById('locationBtn').classList.add('nav-btn-active');

    // Hide the devices panel and make nav pill-shaped
    const panel = document.getElementById('bottomPanel');
    const nav = document.querySelector('.bottom-nav');
    panel.classList.add('hidden');
    nav.classList.remove('panel-visible');

    // Fit map to show all markers
    if (state.markers.length > 0) {
        const group = new L.featureGroup(state.markers);
        state.map.fitBounds(group.getBounds().pad(0.2));
    }
}

function handleDevicesBtn() {
    // Update active state
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('nav-btn-active'));
    document.getElementById('devicesBtn').classList.add('nav-btn-active');

    // Show the devices panel and connect nav to panel
    const panel = document.getElementById('bottomPanel');
    const nav = document.querySelector('.bottom-nav');
    panel.classList.remove('hidden');
    panel.classList.add('expanded');
    nav.classList.add('panel-visible');

    // Update the isExpanded state for drag functionality
    if (panel._setExpanded) {
        panel._setExpanded(true);
    }

    // Filter devices to show only those in current map frame
    filterDevicesInFrame();
}

async function handleRefresh() {
    const refreshBtn = document.getElementById('refreshBtn');
    refreshBtn.classList.add('loading');
    try {
        await fetchLocations();
    } finally {
        setTimeout(() => {
            refreshBtn.classList.remove('loading');
        }, 500);
    }
}

async function handleRefreshClick(event) {
    event.preventDefault();
    event.stopPropagation();
    console.log('Refresh clicked!');
    const refreshBtn = document.getElementById('refreshBtn');
    refreshBtn.classList.add('loading');
    try {
        await fetchLocations();
    } catch (error) {
        console.error('Refresh error:', error);
        showToast('Refresh failed: ' + error.message, 'error');
    } finally {
        setTimeout(() => {
            refreshBtn.classList.remove('loading');
        }, 500);
    }
}

function filterDevicesInFrame() {
    const bounds = state.map.getBounds();
    const devicesList = document.getElementById('devicesList');

    if (state.accessories.length === 0) {
        devicesList.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🎒</div>
                <div class="empty-state-text">No devices yet</div>
                <div class="empty-state-subtext">Add your first device to start tracking</div>
            </div>
        `;
        document.getElementById('devicesCount').textContent = '0';
        return;
    }

    // Filter accessories that have locations in the current map bounds
    const accessoriesInFrame = state.accessories.filter(accessory => {
        const accessoryLocations = state.locations.filter(l => l.accessoryId === accessory.id);
        return accessoryLocations.some(loc =>
            bounds.contains([loc.lat, loc.lng])
        );
    });

    // If no devices in frame, show all
    const accessoriesToShow = accessoriesInFrame.length > 0 ? accessoriesInFrame : state.accessories;

    document.getElementById('devicesCount').textContent = accessoriesToShow.length;

    devicesList.innerHTML = accessoriesToShow.map(accessory => {
        const latestLoc = state.locations
            .filter(l => l.accessoryId === accessory.id)
            .sort((a, b) => b.timestamp - a.timestamp)[0];

        const statusText = latestLoc
            ? `Last seen near ${formatTime(latestLoc.timestamp)}`
            : 'No location data';

        return `
            <div class="device-item" onclick="selectDevice('${accessory.id}')">
                <div class="device-item-icon" style="background: ${accessory.color}20; color: ${accessory.color}">
                    ${iconMap[accessory.icon] || '🏷️'}
                </div>
                <div class="device-item-info">
                    <div class="device-item-name">${accessory.name}</div>
                    <div class="device-item-status">${statusText}</div>
                </div>
                <div class="device-item-arrow">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
                </div>
            </div>
        `;
    }).join('');
}

function formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
}

// ============================================
// DEVICE DETAIL PANEL
// ============================================

function selectDevice(accessoryId) {
    const accessory = state.accessories.find(a => a.id === accessoryId);
    if (!accessory) return;

    state.selectedDeviceId = accessoryId;

    // Update detail panel
    const detailPanel = document.getElementById('deviceDetailPanel');
    document.getElementById('detailDeviceIcon').innerHTML = `<span>${iconMap[accessory.icon] || '🏷️'}</span>`;
    document.getElementById('detailDeviceIcon').style.background = accessory.color + '20';
    document.getElementById('detailDeviceIcon').style.color = accessory.color;

    document.getElementById('detailDeviceName').textContent = accessory.name;

    const latestLoc = state.locations
        .filter(l => l.accessoryId === accessoryId)
        .sort((a, b) => b.timestamp - a.timestamp)[0];

    if (latestLoc) {
        document.getElementById('detailDeviceStatus').textContent =
            `Last seen near ${formatTime(latestLoc.timestamp)}`;
        state.map.setView([latestLoc.lat, latestLoc.lng], 15);
    } else {
        document.getElementById('detailDeviceStatus').textContent = 'No location data';
    }

    // Hide the devices panel
    const panel = document.getElementById('bottomPanel');
    const nav = document.querySelector('.bottom-nav');
    panel.classList.add('hidden');
    nav.classList.remove('panel-visible');

    // Show detail panel
    detailPanel.classList.add('active');
}

function closeDeviceDetail() {
    document.getElementById('deviceDetailPanel').classList.remove('active');
    state.selectedDeviceId = null;
    clearPathLines();

    // Restore the devices panel if devices button is active
    const devicesBtn = document.getElementById('devicesBtn');
    if (devicesBtn.classList.contains('nav-btn-active')) {
        const panel = document.getElementById('bottomPanel');
        const nav = document.querySelector('.bottom-nav');
        panel.classList.remove('hidden');
        panel.classList.add('expanded');
        nav.classList.add('panel-visible');

        // Update the isExpanded state for drag functionality
        if (panel._setExpanded) {
            panel._setExpanded(true);
        }
    }
}

// Swipe-down gesture to close device detail panel
function initDetailPanelSwipe() {
    const detailPanel = document.getElementById('deviceDetailPanel');
    let startY = 0;
    let currentY = 0;
    let isDragging = false;
    const swipeThreshold = 80; // Minimum distance to trigger swipe

    function onStart(e) {
        // Only start if the detail panel is active
        if (!detailPanel.classList.contains('active')) return;

        isDragging = true;
        startY = e.type.includes('mouse') ? e.clientY : e.touches[0].clientY;
        detailPanel.style.transition = 'none';
    }

    function onMove(e) {
        if (!isDragging) return;

        currentY = e.type.includes('mouse') ? e.clientY : e.touches[0].clientY;
        const diff = currentY - startY;

        // Only track swipes down (positive diff)
        if (diff > 0) {
            const opacity = 1 - (diff / (window.innerHeight * 0.5));
            detailPanel.style.transform = `translateY(${diff}px)`;
            detailPanel.style.opacity = opacity > 0 ? opacity : 0;
        }
    }

    function onEnd(e) {
        if (!isDragging) return;
        isDragging = false;

        const diff = currentY - startY;

        // If swiped down far enough, close the panel immediately
        if (diff > swipeThreshold) {
            closeDeviceDetail();
        } else {
            // Reset with animation if not enough swipe
            detailPanel.style.transition = 'transform 0.3s ease, opacity 0.3s ease';
        }

        // Reset transform and opacity
        detailPanel.style.transform = '';
        detailPanel.style.opacity = '';
        detailPanel.style.transition = '';
    }

    // Touch events
    detailPanel.addEventListener('touchstart', onStart, { passive: true });
    document.addEventListener('touchmove', onMove, { passive: true });
    document.addEventListener('touchend', onEnd);
    document.addEventListener('touchcancel', onEnd);

    // Mouse events (for desktop testing)
    detailPanel.addEventListener('mousedown', onStart);
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onEnd);
}

function showDevicePath() {
    if (!state.selectedDeviceId) return;

    const accessoryLocations = state.locations
        .filter(l => l.accessoryId === state.selectedDeviceId)
        .sort((a, b) => a.timestamp - b.timestamp);

    if (accessoryLocations.length < 2) {
        showToast('Need at least 2 location points to show path', 'warning');
        return;
    }

    // Clear existing paths
    clearPathLines();

    // Create path line
    const latLngs = accessoryLocations.map(loc => [loc.lat, loc.lng]);

    const accessory = state.accessories.find(a => a.id === state.selectedDeviceId);

    const polyline = L.polyline(latLngs, {
        color: accessory?.color || '#3B82F6',
        weight: 4,
        opacity: 0.7,
        className: 'location-path'
    }).addTo(state.map);

    state.pathPolylines.push(polyline);

    // Fit map to show path
    state.map.fitBounds(polyline.getBounds(), { padding: [50, 50] });

    showToast(`Showing ${accessoryLocations.length} location points`, 'success');
}

function clearPathLines() {
    state.pathPolylines.forEach(line => state.map.removeLayer(line));
    state.pathPolylines = [];
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

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);

        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: [], days: 1 }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (response.status === 404) {
            showToast('Server reachable but endpoint not found', 'warning');
        } else if (response.status === 401) {
            showToast('Server reachable! Authentication required', 'success');
        } else if (response.status === 200 || response.status === 400) {
            showToast('Connection successful!', 'success');
        } else {
            showToast(`Server responded with status ${response.status}`, 'success');
        }
    } catch (error) {
        if (error.name === 'AbortError') {
            showToast('Connection timed out', 'error');
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
    renderDevicesList();
}

function saveAccessories() {
    localStorage.setItem('haystackAccessories', JSON.stringify(state.accessories));
    renderDevicesList();
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
    fetchLocations(); // Auto-fetch after adding
}

function deleteAccessory(id) {
    if (confirm('Are you sure you want to delete this accessory?')) {
        state.accessories = state.accessories.filter(a => a.id !== id);
        saveAccessories();
        showToast('Accessory deleted', 'success');
    }
}

function renderDevicesList() {
    const devicesList = document.getElementById('devicesList');

    if (state.accessories.length === 0) {
        devicesList.innerHTML = `
            <div class="empty-state">
                <div class="empty-state-icon">🎒</div>
                <div class="empty-state-text">No devices yet</div>
                <div class="empty-state-subtext">Tap + to add your first device</div>
            </div>
        `;
        document.getElementById('devicesCount').textContent = '0';
        return;
    }

    document.getElementById('devicesCount').textContent = state.accessories.length;

    devicesList.innerHTML = state.accessories.map(accessory => {
        const latestLoc = state.locations
            .filter(l => l.accessoryId === accessory.id)
            .sort((a, b) => b.timestamp - a.timestamp)[0];

        const statusText = latestLoc
            ? `Last seen near ${formatTime(latestLoc.timestamp)}`
            : 'No location data';

        return `
            <div class="device-item" onclick="selectDevice('${accessory.id}')">
                <div class="device-item-icon" style="background: ${accessory.color}20; color: ${accessory.color}">
                    ${iconMap[accessory.icon] || '🏷️'}
                </div>
                <div class="device-item-info">
                    <div class="device-item-name">${accessory.name}</div>
                    <div class="device-item-status">${statusText}</div>
                </div>
                <div class="device-item-arrow">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
                </div>
            </div>
        `;
    }).join('');
}

// ============================================
// LOCATION FETCHING
// ============================================

async function fetchLocations() {
    const days = state.settings.daysToFetch;
    const activeAccessories = state.accessories.filter(a => a.active);

    if (activeAccessories.length === 0) {
        showToast('No active devices to fetch', 'warning');
        return;
    }

    try {
        const allLocations = [];

        for (const accessory of activeAccessories) {
            try {
                const hashedKey = await getHashedAdvertisementKey(accessory.privateKey);
                const reports = await fetchLocationReportsFromEndpoint([hashedKey], days);

                for (const report of reports) {
                    try {
                        const decrypted = await decryptReport(report, accessory.privateKey);
                        allLocations.push({
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
                        console.error(`Failed to decrypt report for ${accessory.name}:`, decryptError);
                    }
                }
            } catch (deviceError) {
                console.error(`Failed to fetch for ${accessory.name}:`, deviceError);
            }
        }

        allLocations.sort((a, b) => a.timestamp - b.timestamp);

        state.locations = allLocations;
        updateMapMarkers();
        renderDevicesList();
        showToast(`Fetched ${allLocations.length} location(s)`, 'success');

        if (allLocations.length > 0) {
            const group = new L.featureGroup(state.markers);
            state.map.fitBounds(group.getBounds().pad(0.1));
        }
    } catch (error) {
        console.error('Error fetching locations:', error);
        showToast(`Failed to fetch: ${error.message}`, 'error');
    }
}

function updateMapMarkers() {
    state.markers.forEach(marker => state.map.removeLayer(marker));
    state.markers = [];

    if (state.locations.length === 0) return;

    const locationsByAccessory = {};
    state.locations.forEach(loc => {
        if (!locationsByAccessory[loc.accessoryId]) {
            locationsByAccessory[loc.accessoryId] = [];
        }
        locationsByAccessory[loc.accessoryId].push(loc);
    });

    Object.entries(locationsByAccessory).forEach(([accessoryId, locations]) => {
        const accessory = state.accessories.find(a => a.id === accessoryId);
        if (!accessory) return;

        const latest = locations[locations.length - 1];

        const icon = L.divIcon({
            className: 'custom-marker',
            html: `<div style="background: ${accessory.color}; width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center; justify-content: center; border: 3px solid white; box-shadow: 0 2px 8px rgba(0,0,0,0.3); font-size: 18px;">${iconMap[accessory.icon] || '🏷️'}</div>`,
            iconSize: [36, 36],
            iconAnchor: [18, 18]
        });

        const popupContent = `
            <div class="custom-popup">
                <div class="custom-popup-icon">${iconMap[accessory.icon] || '🏷️'}</div>
                <div class="custom-popup-name">${accessory.name}</div>
                <div class="custom-popup-time">${new Date(latest.timestamp).toLocaleString()}</div>
                <div style="font-size: 12px; margin-top: 4px;">Accuracy: ±${latest.accuracy}m</div>
                ${latest.batteryStatus ? `<div style="font-size: 12px;">Battery: ${latest.batteryStatus}</div>` : ''}
            </div>
        `;

        const marker = L.marker([latest.lat, latest.lng], { icon })
            .addTo(state.map)
            .on('click', () => selectDevice(accessoryId));

        state.markers.push(marker);
    });
}

// ============================================
// IMPORT/EXPORT
// ============================================

function colorComponentsToHex(components) {
    const toHex = (val) => {
        const num = val <= 1 ? Math.round(val * 255) : Math.round(val);
        return num.toString(16).padStart(2, '0');
    };

    if (components && components.length >= 3) {
        const r = toHex(components[0]);
        const g = toHex(components[1]);
        const b = toHex(components[2]);
        return `#${r}${g}${b}`.toUpperCase();
    }
    return '#3B82F6';
}

function deviceIdToHex(id) {
    if (typeof id === 'number') {
        return id.toString(16).toUpperCase().padStart(8, '0');
    }
    return id.toString();
}

function importDeviceJson(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
        try {
            const data = JSON.parse(e.target.result);
            const devices = Array.isArray(data) ? data : [data];

            if (devices.length === 0) {
                showToast('No devices found in file', 'error');
                return;
            }

            const device = devices[0];

            document.getElementById('accessoryName').value = device.name || '';
            document.getElementById('accessoryId').value = deviceIdToHex(device.id);
            document.getElementById('accessoryKey').value = device.privateKey || '';

            const hexColor = colorComponentsToHex(device.colorComponents);
            selectColor(hexColor);

            const iconMapping = {
                '': 'tag', 'tag': 'tag', 'key': 'key', 'bag': 'bag',
                'backpack': 'bag', 'bike': 'bike', 'bicycle': 'bike',
                'car': 'car', 'vehicle': 'car', 'pet': 'pet', 'dog': 'pet', 'cat': 'pet'
            };
            const icon = iconMapping[device.icon] || 'tag';
            selectIcon(icon);

            state.importedIsActive = device.isActive !== undefined ? device.isActive : true;

            showToast(`Loaded "${device.name}" from device.json`, 'success');

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
    event.target.value = '';
}

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
                icon: 'tag',
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

// Expose functions globally for onclick handlers
window.selectDevice = selectDevice;
window.deleteAccessory = deleteAccessory;
window.openAccessoryModal = openAccessoryModal;
window.fetchLocations = fetchLocations;
window.handleRefreshClick = handleRefreshClick;
