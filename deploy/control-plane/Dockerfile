FROM node:22-bookworm-slim AS build

WORKDIR /opt/routecairn
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build:release && npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production
WORKDIR /opt/routecairn
COPY --from=build /opt/routecairn/package.json ./package.json
COPY --from=build /opt/routecairn/node_modules ./node_modules
COPY --from=build /opt/routecairn/dist ./dist
COPY --from=build /opt/routecairn/apps/dashboard-ui/dist ./apps/dashboard-ui/dist
RUN mkdir -p /var/lib/routecairn && chown -R node:node /var/lib/routecairn /opt/routecairn

USER node
EXPOSE 4711
VOLUME ["/var/lib/routecairn"]
ENTRYPOINT ["node", "dist/cli/index.js"]
CMD ["dashboard", "--mode", "server", "--host", "0.0.0.0", "--port", "4711", "--data-dir", "/var/lib/routecairn", "--trust-proxy"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:4711/readyz').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
