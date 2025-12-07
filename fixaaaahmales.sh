#!/bin/bash

echo "🔥 Auto Fix CVE-2025-55182 + Miyomar1337"
echo "========================================="

# Check package.json
if [ ! -f package.json ]; then
  echo "❌ package.json tidak ditemukan!"
  exit 1
fi

echo "📦 Package.json ditemukan, mulai scanning..."

# Grab Next.js version
NEXT_VERSION=$(node -p "require('./package.json').dependencies.next || ''")

echo "📌 Next.js Version terdeteksi: $NEXT_VERSION"

echo "🔧 Updating React + RSC core..."
npm install react@latest react-dom@latest -f
npm install react-server-dom-webpack@latest -f
npm install react-server-dom-parcel@latest -f
npm install react-server-dom-turbopack@latest -f
npm install @vitejs/plugin-rsc@latest -f

# Next.js version-based upgrade
if [[ "$NEXT_VERSION" == 15.0.* ]]; then
  npm install next@15.0.5 -f
elif [[ "$NEXT_VERSION" == 15.1.* ]]; then
  npm install next@15.1.9 -f
elif [[ "$NEXT_VERSION" == 15.2.* ]]; then
  npm install next@15.2.6 -f
elif [[ "$NEXT_VERSION" == 15.3.* ]]; then
  npm install next@15.3.6 -f
elif [[ "$NEXT_VERSION" == 15.4.* ]]; then
  npm install next@15.4.8 -f
elif [[ "$NEXT_VERSION" == 15.5.* ]]; then
  npm install next@15.5.7 -f
elif [[ "$NEXT_VERSION" == 16.0.* ]]; then
  npm install next@16.0.7 -f
elif [[ "$NEXT_VERSION" == 14.3.0-canary.* ]]; then
  echo "⬇ Downgrading to Next.js 14 stable..."
  npm install next@14 -f
else
  echo "⚠ Versi Next.js tidak dikenal → installing secure latest"
  npm install next@latest -f
fi

echo "🧹 Bersihkan cache..."
npm cache verify

echo "🚀 Patch selesai! Memulai auto-restart detection..."

# Auto restart logic
if command -v pm2 >/dev/null 2>&1; then
  echo "🔄 Detected PM2 → Restarting PM2 processes..."
  pm2 restart all
  exit 0
fi

if [ -f "yarn.lock" ]; then
  echo "🔄 Yarn terdeteksi → Restarting app..."
  yarn stop 2>/dev/null
  yarn start
  exit 0
fi

if [ -f "pnpm-lock.yaml" ]; then
  echo "🔄 PNPM terdeteksi → Restarting app..."
  pnpm stop 2>/dev/null
  pnpm start
  exit 0
fi

echo "🔄 Restarting via NPM..."
npm run stop 2>/dev/null
npm run start 2>/dev/null || npm start

echo "✅ DONE! Server sudah di-restart dan patch berhasil diterapkan."
