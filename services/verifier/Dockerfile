FROM node:20-alpine
WORKDIR /app
COPY sdk/ sdk/
RUN cd sdk && npm install && npx tsc
COPY services/verifier/package*.json services/verifier/
RUN cd services/verifier && npm install
COPY services/verifier/src/ services/verifier/src/
EXPOSE 3200
WORKDIR /app/services/verifier
CMD ["npx", "tsx", "src/start.ts"]
