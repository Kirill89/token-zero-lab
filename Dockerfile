# Token Zero lab -- INTENTIONALLY VULNERABLE. For local training only.
# Run it with:  docker compose up --build
#
# NOTE: written without Docker available; not built or run by its author.

FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY app.js ./
CMD ["node", "app.js"]
