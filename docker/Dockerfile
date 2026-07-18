# Build and run the trust certificate server.
#
# Multi-stage so the image that ships carries no compiler and no dev
# dependencies: it is a server that holds people's public keys and their
# assertions, and the less that is in it, the less there is to go wrong.

FROM node:22-alpine AS build
WORKDIR /app
COPY server/package.json server/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY server/tsconfig.json ./
COPY server/src ./src
RUN npm run build

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY server/package.json server/package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /app/dist ./dist

# Runs unprivileged; the node image already provides this user.
USER node
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:8080/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
