# Dockerfile — imagem otimizada para rodar bot-seguranca-grupo
FROM node:18-alpine

# Instala dependências de build para better-sqlite3
RUN apk add --no-cache python3 make g++ sqlite-dev build-base tini

# Create app directory
WORKDIR /usr/src/app

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
# Copia package.json primeiro para caching de camadas
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy app source
COPY . .

# Ajusta permissões
RUN chown -R appuser:appgroup /usr/src/app
RUN chmod -R 700 /usr/src/app/.wwebjs_auth || true

# Expose nothing; container communicates only outbound
ENV NODE_ENV=production
ENV SESSION_DATA_PATH=.wwebjs_auth

# Use tini init to handle PID 1 signals and reap processes
ENTRYPOINT ["/sbin/tini", "--"]
USER appuser
CMD ["node", "index.stable.js"]
