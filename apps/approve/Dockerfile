FROM node:20-alpine
WORKDIR /app
COPY sdk/ sdk/
RUN cd sdk && npm install && npx tsc
COPY apps/approve/package*.json apps/approve/
RUN cd apps/approve && npm install
COPY apps/approve/src/ apps/approve/src/
COPY apps/approve/public/ apps/approve/public/
EXPOSE 3100
WORKDIR /app/apps/approve
CMD ["npx", "tsx", "src/start.ts"]
