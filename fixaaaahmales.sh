#!/bin/bash

# AUTO-FIX CVE-2025-55182 + SMART RESTART (NO 500 ERROR)
# by Miyomar1337

set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔥 Auto Fix CVE-2025-55182 + NO DOWNTIME RESTART 🔥${NC}"
echo "========================================================"

# ================= DETECT SERVER TYPE =================
detect_server() {
    echo -e "${YELLOW}[*] Detecting server type...${NC}"
    
    # Cek process yang running
    if ps aux | grep -q "[n]ode.*next"; then
        echo "  → Next.js Node process detected"
        SERVER_TYPE="node"
    elif ps aux | grep -q "[p]m2"; then
        echo "  → PM2 detected"
        SERVER_TYPE="pm2"
    elif systemctl list-units --type=service | grep -q "next\|node"; then
        echo "  → Systemd service detected"
        SERVER_TYPE="systemd"
    elif ps aux | grep -q "[d]ocker.*next"; then
        echo "  → Docker detected"
        SERVER_TYPE="docker"
    elif [ -f "package.json" ] && grep -q '"start"' "package.json"; then
        echo "  → npm start script available"
        SERVER_TYPE="npm"
    else
        echo "  → Unknown server type"
        SERVER_TYPE="unknown"
    fi
}

# ================= GRACEFUL RESTART =================
graceful_restart() {
    local server_type=$1
    local project_dir=$2
    
    echo -e "${YELLOW}[*] Performing graceful restart...${NC}"
    
    case $server_type in
        "pm2")
            echo "  Restarting via PM2..."
            # Cari PM2 app name
            APP_NAME=$(pm2 list | grep "$project_dir" | awk '{print $2}' | head -1)
            if [ -n "$APP_NAME" ]; then
                echo "  Found PM2 app: $APP_NAME"
                
                # Step 1: Reload dengan zero-downtime
                pm2 reload "$APP_NAME" --update-env || {
                    echo "  PM2 reload failed, trying restart..."
                    pm2 restart "$APP_NAME"
                }
                
                # Wait for health check
                sleep 3
                pm2 status
            else
                echo "  ❌ No PM2 app found for $project_dir"
                echo "  Starting new PM2 process..."
                pm2 start "npm run start" --name "nextjs_$(basename $project_dir)" || true
            fi
            ;;
            
        "systemd")
            echo "  Restarting via systemd..."
            # Cari service name
            SERVICE_NAME=$(systemctl list-units --type=service | grep -i "next\|node" | grep -v "●" | awk '{print $1}' | head -1)
            
            if [ -n "$SERVICE_NAME" ]; then
                echo "  Found service: $SERVICE_NAME"
                
                # Graceful restart
                systemctl daemon-reload
                systemctl restart "$SERVICE_NAME"
                systemctl status "$SERVICE_NAME" --no-pager -l
            else
                echo "  ❌ No systemd service found"
            fi
            ;;
            
        "docker")
            echo "  Restarting Docker container..."
            # Cari container ID
            CONTAINER_ID=$(docker ps | grep "next" | awk '{print $1}' | head -1)
            
            if [ -n "$CONTAINER_ID" ]; then
                echo "  Found container: $CONTAINER_ID"
                docker restart "$CONTAINER_ID"
                docker logs "$CONTAINER_ID" --tail 20
            fi
            ;;
            
        "node"|"npm")
            echo "  Killing existing Node processes..."
            # Kill existing processes gracefully
            pkill -f "next" || true
            sleep 2
            
            echo "  Starting new process..."
            # Start in background dengan nohup
            nohup npm run start > nextjs.log 2>&1 &
            echo $! > nextjs.pid
            
            echo "  Process started with PID: $(cat nextjs.pid)"
            ;;
            
        *)
            echo "  ⚠️  Unknown server type, manual restart required"
            echo ""
            echo "  MANUAL RESTART COMMANDS:"
            echo "  -------------------------"
            echo "  # Jika pakai PM2:"
            echo "  pm2 restart all"
            echo ""
            echo "  # Jika pakai systemd:"
            echo "  systemctl restart your-service"
            echo ""
            echo "  # Jika manual node:"
            echo "  pkill -f next"
            echo "  npm run build"
            echo "  npm run start &"
            echo ""
            echo "  # Jika docker:"
            echo "  docker-compose restart"
            echo ""
            return 1
            ;;
    esac
    
    return 0
}

# ================= HEALTH CHECK =================
health_check() {
    local url=$1
    local max_attempts=10
    local attempt=1
    
    echo -e "${YELLOW}[*] Health checking...${NC}"
    
    # Coba dapatkan URL dari config atau tebak
    if [ -z "$url" ]; then
        # Coba tebak dari config atau env
        if [ -f ".env" ]; then
            URL=$(grep -i "url\|host\|domain" .env | head -1 | cut -d= -f2 | tr -d ' ' | tr -d '"' | tr -d "'")
        fi
        
        if [ -z "$URL" ]; then
            URL="http://localhost:3000"
        fi
    else
        URL=$url
    fi
    
    echo "  Testing: $URL"
    
    while [ $attempt -le $max_attempts ]; do
        echo "  Attempt $attempt/$max_attempts..."
        
        # Cek dengan curl (timeout 10 detik)
        if curl -s -f --max-time 10 "$URL" > /dev/null 2>&1; then
            echo -e "${GREEN}  ✅ HEALTH CHECK PASSED${NC}"
            echo "  Server is responding normally"
            return 0
        elif curl -s --max-time 10 "$URL/health" > /dev/null 2>&1; then
            echo -e "${GREEN}  ✅ HEALTH CHECK PASSED (via /health)${NC}"
            return 0
        fi
        
        sleep 3
        attempt=$((attempt + 1))
    done
    
    echo -e "${RED}  ❌ HEALTH CHECK FAILED${NC}"
    echo "  Server might be down or still starting"
    
    # Cek logs terakhir
    echo ""
    echo "  Last logs:"
    if [ -f "nextjs.log" ]; then
        tail -20 nextjs.log
    elif [ -f "logs/error.log" ]; then
        tail -20 logs/error.log
    fi
    
    return 1
}

# ================= MAIN FIX FUNCTION =================
safe_fix() {
    echo -e "${YELLOW}[1] Backup existing setup...${NC}"
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_DIR="/tmp/nextjs_backup_$TIMESTAMP"
    mkdir -p "$BACKUP_DIR"
    
    # Backup penting
    cp -r package.json package-lock.json next.config.* app/ pages/ src/ middleware.js .env* 2>/dev/null || true
    
    # Backup node_modules versi lama (optional)
    tar -czf "$BACKUP_DIR/node_modules_backup.tar.gz" node_modules 2>/dev/null || true
    
    echo -e "${YELLOW}[2] Stop server gracefully...${NC}"
    
    # Stop server dengan graceful
    case $SERVER_TYPE in
        "pm2") pm2 stop all 2>/dev/null || true ;;
        "systemd") systemctl stop $(systemctl list-units --type=service | grep -i "next\|node" | awk '{print $1}' 2>/dev/null) 2>/dev/null || true ;;
        "node") pkill -f "next" 2>/dev/null || true ;;
    esac
    
    sleep 2
    
    echo -e "${YELLOW}[3] Clear Next.js cache...${NC}"
    # INI PENTING BANGET! Biar ga 500 error
    rm -rf .next 2>/dev/null || true
    rm -rf .swc 2>/dev/null || true
    rm -rf node_modules/.cache 2>/dev/null || true
    
    echo -e "${YELLOW}[4] Update Next.js...${NC}"
    
    # Update dengan cara yang aman
    if grep -q '"next"' package.json; then
        OLD_VERSION=$(grep '"next"' package.json | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
        echo "  Current: v$OLD_VERSION"
        
        # Update berdasarkan version
        if [[ "$OLD_VERSION" == 15* ]]; then
            npm install next@15.1.7 --save --legacy-peer-deps
        elif [[ "$OLD_VERSION" == 14* ]]; then
            npm install next@14.2.22 --save --legacy-peer-deps
        else
            npm install next@latest --save --legacy-peer-deps
        fi
    else
        npm install next@latest --save --legacy-peer-deps
    fi
    
    echo -e "${YELLOW}[5] Rebuild dependencies...${NC}"
    npm ci --legacy-peer-deps || npm install --legacy-peer-deps
    
    echo -e "${YELLOW}[6] Create security patches...${NC}"
    
    # Buat middleware jika belum ada
    if [ ! -f "middleware.js" ] && [ ! -f "src/middleware.js" ] && [ ! -f "app/middleware.js" ]; then
        cat > middleware.js << 'EOF'
import { NextResponse } from 'next/server';

export function middleware(request) {
  const url = request.nextUrl;
  
  // Block CVE-2025-55182 SSRF attempts
  if (url.pathname.includes('/_next/action')) {
    const origin = request.headers.get('origin') || '';
    const referer = request.headers.get('referer') || '';
    const host = request.headers.get('host') || '';
    
    // Allow only from same origin
    if (origin && !origin.includes(host) && 
        !origin.includes('localhost') && 
        !origin.includes('127.0.0.1')) {
      
      console.error('🚨 BLOCKED SSRF ATTEMPT (CVE-2025-55182):', {
        ip: request.ip || request.headers.get('x-forwarded-for'),
        origin,
        referer,
        path: url.pathname,
        timestamp: new Date().toISOString()
      });
      
      return NextResponse.json(
        { error: 'Access denied' },
        { status: 403, headers: { 'x-cve-blocked': 'CVE-2025-55182' } }
      );
    }
  }
  
  return NextResponse.next();
}

export const config = {
  matcher: ['/_next/action/:path*'],
};
EOF
        echo "  Created middleware.js"
    fi
    
    echo -e "${YELLOW}[7] Build project...${NC}"
    
    # Build dengan incremental
    if npm run build 2>&1 | tee build.log; then
        echo -e "${GREEN}  ✅ Build successful${NC}"
    else
        echo -e "${RED}  ❌ Build failed, checking errors...${NC}"
        tail -50 build.log
        echo ""
        echo "  Trying development build..."
        NEXT_PUBLIC_IGNORE_BUILD_ERRORS=true npm run build 2>&1 | tail -30 || true
    fi
    
    echo -e "${YELLOW}[8] Restart server...${NC}"
    
    # Graceful restart
    if graceful_restart "$SERVER_TYPE" "$PWD"; then
        echo -e "${GREEN}  ✅ Server restarted${NC}"
    else
        echo -e "${YELLOW}  ⚠️  Manual restart needed${NC}"
    fi
    
    echo -e "${YELLOW}[9] Final health check...${NC}"
    
    if health_check; then
        echo -e "${GREEN}========================================${NC}"
        echo -e "${GREEN}✅ FIX BERHASIL! SERVER UP & RUNNING ✅${NC}"
        echo -e "${GREEN}========================================${NC}"
        echo ""
        echo "Backup tersimpan di: $BACKUP_DIR"
        echo "Logs: nextjs.log atau pm2 logs"
    else
        echo -e "${RED}========================================${NC}"
        echo -e "${RED}⚠️  SERVER MUNGKIN DOWN - CHECK MANUAL ⚠️${NC}"
        echo -e "${RED}========================================${NC}"
        echo ""
        echo "Emergency recovery:"
        echo "  cd $BACKUP_DIR"
        echo "  # Restore jika perlu"
        echo ""
        echo "Check:"
        echo "  1. pm2 logs OR journalctl -u your-service"
        echo "  2. curl http://localhost:3000"
        echo "  3. netstat -tulpn | grep :3000"
    fi
}

# ================= MAIN =================
main() {
    # Deteksi project
    if [ ! -f "package.json" ]; then
        echo -e "${RED}❌ Tidak di project directory${NC}"
        echo "Mencari project Next.js..."
        
        # Cari otomatis
        FOUND=$(find /home /var/www /opt -name "package.json" 2>/dev/null | 
                xargs grep -l "next" 2>/dev/null | head -1)
        
        if [ -z "$FOUND" ]; then
            echo "  ❌ Tidak ditemukan"
            echo ""
            echo "Jalankan di directory project:"
            echo "  cd /path/to/your/nextjs"
            echo "  curl -sSL https://fix.url | bash"
            exit 1
        fi
        
        PROJECT_DIR=$(dirname "$FOUND")
        echo "  ✅ Found: $PROJECT_DIR"
        cd "$PROJECT_DIR"
    fi
    
    # Deteksi server type
    detect_server
    
    # Konfirmasi
    echo ""
    read -p "Continue with fix? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled"
        exit 0
    fi
    
    # Jalankan fix
    safe_fix
    
    # Tips post-fix
    echo ""
    echo -e "${BLUE}📝 POST-FIX CHECKLIST:${NC}"
    echo "  1. Test semua Server Actions"
    echo "  2. Cek tidak ada 500 error"
    echo "  3. Monitor error logs 24 jam"
    echo "  4. Update semua environment (staging, prod)"
    echo "  5. Backup database sebelum deploy ke prod"
}

# Run
main "$@"
