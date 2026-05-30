FROM node:22-slim

WORKDIR /app

# Install deps deterministically — `npm ci` honours package-lock.json exactly.
# The previous `|| npm install` fallback weakened lockfile reproducibility and
# was caught by audit F11; if `npm ci` fails the build SHOULD fail so the
# operator sees the lockfile drift instead of silently picking new versions.
# tsx moved into "dependencies" so --omit=dev still installs it (audit F11).
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Copy source
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts

# The node:22-slim image ships with a non-root `node` user (UID 1000). Hand
# ownership of /app to it before dropping privileges so npm can read its files.
RUN chown -R node:node /app

USER node

ENV NODE_ENV=production

# tsx is installed as a regular dep above, so this resolves to
# node_modules/.bin/tsx without `npx` fan-out. Direct `node_modules/.bin/tsx`
# invocation keeps PATH resolution predictable in the container.
CMD ["./node_modules/.bin/tsx", "src/seller.ts"]
