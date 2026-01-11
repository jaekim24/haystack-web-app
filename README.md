# Macless Haystack - Device Tracker

A web application for tracking your devices. Implements secp224r1 elliptic curve cryptography for decryption entirely in the browser.

---

# Privacy & Data Flow

## What Happens Locally (in your browser)
- All **decryption** of location data happens locally using secp224r1 elliptic curve cryptography
- Device/keys are stored in localStorage
- Map rendering with markers happens locally

## External Connections
1. **Your endpoint** - The app fetches encrypted location data from whatever endpoint you configure in Settings (default: `http://localhost:6176`)

2. **CDNs** - Libraries are loaded from:
   - `unpkg.com` - Leaflet.js (map)
   - `cdn.skypack.dev` - Noble crypto libraries
   - `esm.sh` - Noble ciphers

3. **Map tiles** - The map loads tiles from Esri World Imagery server (for satellite view)

## Privacy Summary
- The app **does not** send any data to third-party services
- It only fetches from **your configured endpoint**
- Decryption is 100% local
- If your endpoint is local (`localhost:6176`), then nothing leaves your network except the CDN/library loads and map tiles

## Fully Offline / Local Setup

If you want to be fully offline/local, you'd need to:

1. **Host the JS libraries locally** instead of using CDNs
   - Download Leaflet.js and serve from your local server
   - Download the Noble crypto libraries and serve locally

2. **Use a local map tile server** instead of Esri
   - Set up a tile server like TileServer GL, MapProxy, or use offline map tiles
