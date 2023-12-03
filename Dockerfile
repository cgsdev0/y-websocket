FROM node:20-alpine

RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app
WORKDIR /home/node/app
COPY package*.json ./
RUN npm install
USER node
COPY --chown=node:node . .
RUN mkdir sqlite
EXPOSE 1234
CMD [ "npm", "start" ]
