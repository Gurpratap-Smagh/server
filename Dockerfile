# Use a slim, stable Node base
FROM node:20-slim

# App dir
WORKDIR /app

# Install only what's needed for prod (uses your package-lock)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy the rest of the code
COPY . .

# Your server listens on process.env.PORT or 8000 by default
# (we set a sane default; you can override at runtime)
ENV NODE_ENV=production
ENV PORT=8000

# Expose the default internal port (override mapping at run time if PORT differs)
EXPOSE 8000

# Run as non-root for safety
USER node

# Start command matches your package.json
CMD ["node", "server.js"]
