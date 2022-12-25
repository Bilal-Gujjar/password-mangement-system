FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
COPY package*.json ./
RUN npm install

# Bundle app source
COPY . .

# Build the app
RUN npm run build

# Set the app port
ENV PORT 3000



# Expose the app port
EXPOSE 3000

# Start the app
CMD [ "npm", "start" ]