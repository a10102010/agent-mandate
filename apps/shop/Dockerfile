FROM node:20-alpine
WORKDIR /app
COPY sdk/ sdk/
RUN cd sdk && npm install && npx tsc
COPY services/verifier/package*.json services/verifier/
COPY services/verifier/src/ services/verifier/src/
RUN cd services/verifier && npm install
COPY apps/shop/package*.json apps/shop/
RUN cd apps/shop && npm install
COPY apps/shop/src/ apps/shop/src/
EXPOSE 3300
WORKDIR /app/apps/shop
CMD ["npx", "tsx", "src/start.ts"]
