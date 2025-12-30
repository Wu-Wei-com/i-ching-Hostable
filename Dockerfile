# Dockerfile
# Use a maintained Node LTS image; multi-stage to keep final smaller.
FROM node:20-alpine AS deps
WORKDIR /app

# Install only prod deps
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy app code (owned by node user)
COPY --chown=node:node . .

# Drop privileges
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://127.0.0.1:3000/healthz',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "server.js"]
