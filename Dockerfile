FROM node:26-alpine
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
ENV NODE_ENV=production PORT=8300 DATA_DIR=/data
VOLUME /data
EXPOSE 8300
USER node
CMD ["node", "server.js"]
