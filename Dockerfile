# Use an official Go image as the base
FROM golang:1.23-alpine AS build

# Install necessary dependencies
RUN apk add --no-cache nodejs npm bash

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./

# Download Go module dependencies
RUN go mod download

# Install templ tool for generating templates
RUN go install github.com/a-h/templ/cmd/templ@latest

# Install TailwindCSS and Flowbite as local project dependencies
COPY package.json package-lock.json ./
RUN npm install

# Copy the rest of the application code
COPY . .

# Build the Go application and run TailwindCSS
RUN templ generate && npx tailwindcss -i styles/input.css -o public/globals.css && go build -tags dev -o ./tmp/main.exe .

# Use a smaller base image for the final stage
FROM alpine:latest

# Install any necessary libraries for the binary (if needed)
RUN apk --no-cache add ca-certificates

# Set work directory for the final image
WORKDIR /root/

# Copy the Go binary from the build stage
COPY --from=build /app/tmp/main.exe .

# Expose any necessary ports (if applicable, for web servers)
EXPOSE 3000

# Command to run the executable
CMD ["./main.exe"]
