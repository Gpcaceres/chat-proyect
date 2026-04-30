FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install --production

# Python3 + Pillow para el análisis de esteganografía (LSB, chi-square, etc.)
RUN apk add --no-cache python3 py3-pip && \
    pip3 install --no-cache-dir --break-system-packages Pillow

COPY . .

RUN mkdir -p uploads

EXPOSE 3000

CMD ["npm", "start"]
