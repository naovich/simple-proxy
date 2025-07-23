const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cors = require('cors');
const fs = require('fs');
const url = require('url');
const http = require('http');
const https = require('https');

class ProxyServer {
  constructor() {
    this.app = express();
    this.config = this.loadConfig();
    this.setupMiddleware();
    this.setupHttpProxy();
  }

  loadConfig() {
    try {
      const configData = fs.readFileSync('./config.json', 'utf8');
      return JSON.parse(configData);
    } catch (error) {
      console.error('Erreur lors du chargement de la configuration:', error.message);
      return {
        port: 8888,
        mode: 'passthrough',
        whitelist: [],
        blacklist: []
      };
    }
  }

  setupMiddleware() {
    this.app.use(cors());
    this.app.use(express.json());
    
    this.app.get('/status', (req, res) => {
      res.json({
        status: 'running',
        mode: this.config.mode,
        port: this.config.port,
        whitelist: this.config.whitelist,
        blacklist: this.config.blacklist
      });
    });

    this.app.post('/config', (req, res) => {
      try {
        this.config = { ...this.config, ...req.body };
        fs.writeFileSync('./config.json', JSON.stringify(this.config, null, 2));
        res.json({ message: 'Configuration mise à jour', config: this.config });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
  }

  isUrlAllowed(targetUrl) {
    const parsedUrl = url.parse(targetUrl);
    const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;

    switch (this.config.mode) {
      case 'whitelist':
        return this.config.whitelist.some(allowed => 
          baseUrl.startsWith(allowed) || targetUrl.startsWith(allowed)
        );
      
      case 'blacklist':
        return !this.config.blacklist.some(blocked => 
          baseUrl.startsWith(blocked) || targetUrl.startsWith(blocked)
        );
      
      case 'passthrough':
      default:
        return true;
    }
  }

  setupHttpProxy() {
    // Proxy HTTP standard pour toutes les requêtes
    this.app.use('/', (req, res, next) => {
      const clientIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || 'unknown';
      const timestamp = new Date().toISOString();
      
      // Construire l'URL complète de la requête
      const protocol = req.headers['x-forwarded-proto'] || 'https';
      const host = req.headers.host;
      let targetUrl;
      
      // Si c'est une requête pour notre API de status/config, on passe
      if (req.path === '/status' || req.path === '/config') {
        return next();
      }
      
      // Extraire l'URL de destination depuis l'URL de la requête
      if (req.originalUrl.startsWith('http://') || req.originalUrl.startsWith('https://')) {
        targetUrl = req.originalUrl;
      } else {
        // Construire l'URL depuis les headers
        const fullUrl = req.originalUrl.slice(1); // Enlever le premier /
        if (fullUrl.startsWith('http://') || fullUrl.startsWith('https://')) {
          targetUrl = fullUrl;
        } else {
          targetUrl = `https://${fullUrl}`;
        }
      }

      console.log(`\n📡 [${timestamp}] Nouvelle requête`);
      console.log(`👤 Client: ${clientIp}`);
      console.log(`🔗 Méthode: ${req.method}`);
      console.log(`📍 URL originale: ${req.originalUrl}`);
      console.log(`🎯 Target calculé: ${targetUrl}`);
      console.log(`🛡️ Mode de filtrage: ${this.config.mode}`);

      if (!this.isUrlAllowed(targetUrl)) {
        console.log(`🚫 BLOQUÉ: Accès refusé pour ${targetUrl} (Mode: ${this.config.mode})`);
        return res.status(403).json({ 
          error: `Accès refusé pour ${targetUrl}. Mode: ${this.config.mode}` 
        });
      }

      console.log(`✅ AUTORISÉ: Redirection vers ${targetUrl}`);

      const proxy = createProxyMiddleware({
        target: targetUrl,
        changeOrigin: true,
        pathRewrite: (path, req) => {
          // Retourner juste le path sans l'URL complète
          const parsed = url.parse(targetUrl);
          return parsed.path || '/';
        },
        onError: (err, req, res) => {
          console.log(`❌ [${new Date().toISOString()}] ERREUR PROXY:`);
          console.log(`   Client: ${clientIp}`);
          console.log(`   Target: ${targetUrl}`);
          console.log(`   Erreur: ${err.message}`);
          if (!res.headersSent) {
            res.status(500).json({ error: 'Erreur de proxy: ' + err.message });
          }
        },
        onProxyReq: (proxyReq, req, res) => {
          console.log(`🚀 [${new Date().toISOString()}] ENVOI:`);
          console.log(`   ${req.method} ${targetUrl}`);
        },
        onProxyRes: (proxyRes, req, res) => {
          console.log(`📨 [${new Date().toISOString()}] RÉPONSE:`);
          console.log(`   Status: ${proxyRes.statusCode}`);
          console.log(`   Content-Type: ${proxyRes.headers['content-type'] || 'non défini'}`);
          console.log(`   Client: ${clientIp} -> ${targetUrl}`);
          console.log(`────────────────────────────────────────`);
        }
      });

      proxy(req, res, next);
    });
  }

  start() {
    const server = this.app.listen(this.config.port, () => {
      console.log(`🚀 Serveur proxy démarré sur le port ${this.config.port}`);
      console.log(`📋 Mode: ${this.config.mode}`);
      console.log(`🔗 Status: http://localhost:${this.config.port}/status`);
      console.log(`⚙️ Configuration: http://localhost:${this.config.port}/config`);
      console.log(`📦 Usage: Définir HTTP_PROXY=http://localhost:${this.config.port}`);
    });

    // Gérer les connexions CONNECT pour HTTPS
    server.on('connect', (req, clientSocket, head) => {
      const timestamp = new Date().toISOString();
      const targetUrl = `https://${req.url}`;
      
      console.log(`\n🔒 [${timestamp}] Connexion HTTPS CONNECT`);
      console.log(`🎯 Target: ${targetUrl}`);
      console.log(`🛡️ Mode: ${this.config.mode}`);

      if (!this.isUrlAllowed(targetUrl)) {
        console.log(`🚫 BLOQUÉ: HTTPS CONNECT refusé pour ${targetUrl}`);
        clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        clientSocket.end();
        return;
      }

      console.log(`✅ AUTORISÉ: HTTPS CONNECT vers ${targetUrl}`);

      const [host, port] = req.url.split(':');
      const serverSocket = require('net').createConnection(port || 443, host, () => {
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        serverSocket.pipe(clientSocket);
        clientSocket.pipe(serverSocket);
      });

      serverSocket.on('error', (err) => {
        console.log(`❌ Erreur serverSocket: ${err.message}`);
        if (!clientSocket.destroyed) {
          clientSocket.end();
        }
      });

      clientSocket.on('error', (err) => {
        console.log(`❌ Erreur clientSocket: ${err.message}`);
        if (!serverSocket.destroyed) {
          serverSocket.end();
        }
      });

      clientSocket.on('close', () => {
        if (!serverSocket.destroyed) {
          serverSocket.end();
        }
      });

      serverSocket.on('close', () => {
        if (!clientSocket.destroyed) {
          clientSocket.end();
        }
      });
    });
  }
}

const server = new ProxyServer();
server.start();