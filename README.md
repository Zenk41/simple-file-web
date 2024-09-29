
# Simple File Web

A simple web application built using Go Fiber, HTMX, and Alpine.js for managing files, integrated with Garage S3 storage. This project allows users to upload, view, and delete files with a lightweight frontend experience using minimal JavaScript.

## Features

- **File Upload**: Easily upload files to Garage S3 storage with real-time feedback.
- **File Listing**: View uploaded files dynamically in a responsive list.
- **Delete Files**: Remove files seamlessly from the storage backend without page reloads.
- **Lightweight Frontend**: Utilizes HTMX and Alpine.js for interactivity with a simple and intuitive interface.
- **Garage S3 Integration**: Connect directly to Garage S3 for efficient file management.

## Technologies

### Backend

- **Go Fiber**: Provides a fast and flexible web server.

### Frontend

- **HTMX**: Enables dynamic interactions without relying on heavy JavaScript frameworks.
- **Alpine.js**: Lightweight and reactive library for adding simple interactivity.

### Storage

- **Garage S3**: Integrated for object storage management.

## Setup

Ensure the following environment variables are set in your `.env` file or exported in your shell:

```bash
export S3_ACCESS_KEY_ID=your_access_key_id
export S3_SECRET_ACCESS_KEY=your_secret_access_key
export S3_BUCKET_NAME=your_bucket_name
export AWS_REGION=your_bucket_region
```

## Run with Docker

To quickly build and run the application using Docker, follow the steps below:

### Build the Docker Image

```
docker build -t simple-file-web .
```

### Run the Docker Container

```
docker run -p 3000:3000 --env-file .env simple-file-web
```
