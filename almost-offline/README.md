# Almost Offline Files

This folder contains locally downloaded versions of external libraries used by the Macless Haystack web app.

## Files Included:

1. **leaflet.css** (14.8 KB) - Leaflet map styles
2. **leaflet.js** (147 KB) - Leaflet map library
3. **images/** - Leaflet marker icons
   - marker-icon.png
   - marker-icon-2x.png
   - marker-shadow.png

## How to Use:

Use `index-offline.html` instead of `index.html` to run the app with local Leaflet files.

```bash
python3 -m http.server 9000
# Then open: http://localhost:9000/index-offline.html
```

## What's Still External:

The crypto libraries (@noble/hashes, @noble/curves, @noble/ciphers) are still loaded from CDN because they are ES modules with complex dependencies that would require bundling with webpack/esbuild to run fully offline.

Map tiles are still loaded from Esri World Imagery server.

## Privacy:

- **Leaflet** - Local (no external requests)
- **Crypto libraries** - CDN (cdn.skypack.dev, esm.sh)
- **Map tiles** - Esri World Imagery (server)
- **Your endpoint** - Only place your data goes

To go fully offline, you would need to:
1. Bundle the crypto libraries with a tool like esbuild
2. Host your own map tile server
