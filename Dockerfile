FROM node:18-alpine3.16

USER node:node
RUN mkdir -p /home/node/workdir
WORKDIR /home/node/workdir

COPY --chown=node:node frontend ./frontend
RUN cd frontend && npm ci && npm run build

COPY --chown=node:node backend ./backend
RUN cd backend && npm ci && npm run build

WORKDIR /home/node/workdir/backend
CMD [ "npm", "start" ]
