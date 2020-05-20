# This Dockerfile is intended for running this site in k8s — there's also a now.json for deploying it in serverless mode

# Builder ---
FROM node:14-alpine as builder

ENV NEXT_TELEMETRY_DISABLED=1 NODE_ENV=production

WORKDIR /app

COPY package.json yarn.lock /app/
RUN yarn install --frozen-lockfile --non-interactive --production=false

COPY . .
RUN sed -i s/serverless/server/g next.config.js
RUN yarn build

# Runner ---
FROM node:14-alpine

ENV NEXT_TELEMETRY_DISABLED=1 NODE_ENV=production

WORKDIR /app

COPY --from=builder /app/.next /app/.next
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/package.json /app/
COPY --from=builder /app/pages /app/pages
COPY --from=builder /app/public /app/public

ARG COMMIT_SHA
ARG COMMIT_REF
ENV COMMIT_SHA=$COMMIT_SHA
ENV COMMIT_REF=$COMMIT_REF

EXPOSE 3000/tcp

CMD yarn start

# https://github.com/nodejs/docker-node/blob/master/docs/BestPractices.md#non-root-user
USER node
