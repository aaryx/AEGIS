FROM node:24.14.1-alpine3.23 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1 API_INTERNAL_URL=http://api:8000
RUN npm run build

FROM node:24.14.1-alpine3.23
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
RUN apk upgrade --no-cache && rm -rf /usr/local/lib/node_modules/npm /opt/yarn* \
    && addgroup -g 10001 aegis && adduser -D -u 10001 -G aegis aegis
COPY --from=build --chown=aegis:aegis /app/.next/standalone ./
COPY --from=build --chown=aegis:aegis /app/.next/static ./.next/static
USER aegis
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s CMD node -e "fetch('http://localhost:3000').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
