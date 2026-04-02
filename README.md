# OpenAPI-First API Starter

An OpenAPI-first development approach for building type-safe REST APIs with automatic code generation, validation, and Docker deployment.

## Overview

This project provides a streamlined workflow where you can:

1. Define your API using OpenAPI 3.0 specification
2. Automatically generate TypeScript types and controller scaffolds
3. Build and deploy a fully validated, production-ready API in Docker

## Features

- **OpenAPI-First Development** - Define your API spec once, generate everything else
- **Automatic Type Generation** - TypeScript types generated from OpenAPI spec
- **Controller Scaffolding** - Auto-generate typed controller stubs
- **Runtime Validation** - Request/response validation against OpenAPI spec
- **Docker Ready** - Multi-stage build for optimized production containers
- **Type Safety** - End-to-end type safety from spec to implementation
- **Code Quality** - ESLint and Prettier included

## Prerequisites

- **Node.js** 24.x or higher
- **Docker** and **Docker Compose**
- **npm**

# 🧩 Using This Template Repository

This repository is configured as a **GitHub Template Repository**, allowing you to quickly create a new project with the same structure, configuration, and files — without copying the entire commit history.

---

## 🚀 How to Create a New Repository from This Template

### Option 1 — Using GitHub Web Interface

1. Go to this repository’s main page on GitHub.
2. Click the green button **“Use this template”** at the top right of the page.
3. Select **“Create a new repository.”**
4. Enter the **name** of your new repository.
5. Choose whether it should be **Public** or **Private.**
6. (Optional) Add a **description** and adjust settings as needed.
7. Click **“Create repository from template.”**

That’s it! 🎉  
Your new repository will now include all the files, folders, and configuration from this template — ready for customization.

---

### Option 2 — Using GitHub CLI (if you prefer the terminal)

You can use the [GitHub CLI](https://cli.github.com/) to create a new repo from the template:

````bash
# Syntax
gh repo create <new-repo-name> --template <owner>/<template-repo>

# Example
gh repo create my-new-project --template GiganticPlayground/openapi-first-template


## Quick Start

### 1. Add Your OpenAPI Specification

Copy your `openapi.yaml` file to the `api/` directory:

```bash
cp your-api-spec.yaml api/openapi.yaml
````

### 2. Install Dependencies

```bash
npm install
```

### 3. Run Complete Setup

This single command will:

- Generate TypeScript types from your OpenAPI spec
- Generate controller scaffolds
- Compile TypeScript to JavaScript
- Build the Docker image
- Start the container

```bash
npm run setup
```

### 4. Access Your API

Your API is now running at:

- **API Endpoint**: http://localhost:3000
- **Swagger UI**: http://localhost:3000/api-docs
- **Health Check**: http://localhost:3000/health

## Manual Setup (Step-by-Step)

If you prefer to run each step individually:

### Generate TypeScript Types

```bash
npm run gen-types
```

Generates `src/types/schema.d.ts` from `api/openapi.yaml`

### Generate Controller Scaffolds

```bash
npm run gen-controllers
```

Creates controller files in `src/controllers/` based on OpenAPI operations

### Build TypeScript

```bash
npm run build
```

Compiles TypeScript source to JavaScript in `dist/` folder

### Build Docker Image

```bash
npm run docker:build
# or
docker-compose build
```

### Start Docker Container

```bash
npm run docker:up
# or
docker-compose up -d
```

## Available Scripts

### Development

- `npm run dev` - Start development server with hot reload
- `npm run gen-types` - Generate TypeScript types from OpenAPI spec
- `npm run gen-controllers` - Generate controller scaffolds
- `npm run generate` - Run both gen-types and gen-controllers

### Production

- `npm run build` - Compile TypeScript to JavaScript
- `npm run start` - Run compiled production code (used in Docker)
- `npm run setup` - Complete automated setup (generate → build → docker)

### Docker

- `npm run docker:build` - Build Docker image
- `npm run docker:up` - Start container in background
- `npm run docker:down` - Stop and remove container
- `npm run docker:logs` - View container logs

### Code Quality

- `npm run lint` - Check code for linting errors
- `npm run lint:fix` - Fix auto-fixable linting errors
- `npm run format` - Format code with Prettier
- `npm run format:check` - Check code formatting
- `npm run type-check` - Run TypeScript type checking
- `npm run validate` - Run type-check + lint + format-check

## Project Structure

```
.
├── api/
│   └── openapi.yaml              # OpenAPI 3.0 specification
├── src/
│   ├── index.ts                  # Application entry point
│   ├── config/                   # Configuration and env validation
│   ├── controllers/              # Auto-generated & manual controllers
│   ├── middlewares/              # Express middlewares (OpenAPI, error handling)
│   ├── types/
│   │   ├── schema.d.ts          # Auto-generated TypeScript types
│   │   └── api-helpers.ts       # Type utilities
│   └── utils/                    # Utilities (logger, etc.)
├── scripts/
│   ├── generate-controllers.js   # Controller generation script
│   └── setup.sh                  # Automated setup script
├── dist/                         # Compiled JavaScript (gitignored)
├── Dockerfile                    # Multi-stage production build
├── docker-compose.yml            # Docker Compose configuration
└── package.json                  # Dependencies and scripts
```

## OpenAPI Requirements

Your `openapi.yaml` must include these custom extensions for proper code generation:

```yaml
paths:
  /users:
    get:
      x-eov-operation-id: getUsers # Unique operation identifier
      x-eov-operation-handler: userController # Controller file name
      summary: Get all users
      # ... rest of operation definition
```

### Required Extensions

- **x-eov-operation-id**: Unique identifier for the operation (becomes function name)
- **x-eov-operation-handler**: Controller file name (without .ts extension)

## Development Workflow

1. **Edit OpenAPI Spec** - Modify `api/openapi.yaml` to add/update endpoints
2. **Regenerate Code** - Run `npm run generate` to update types and controllers
3. **Implement Logic** - Add business logic to generated controller functions
4. **Test Locally** - Run `npm run dev` for local development with hot reload
5. **Validate** - Run `npm run validate` to check types, linting, and formatting
6. **Deploy** - Run `npm run setup` to rebuild and redeploy in Docker

## Environment Variables

Copy `.env.example` to `.env` and configure as needed:

```bash
cp .env.example .env
```

Available variables:

- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)

## How It Works

### 1. Type Generation

Uses `openapi-typescript` to convert OpenAPI schemas into TypeScript types, providing full type safety across your application.

### 2. Controller Generation

Custom script reads your OpenAPI spec and generates Express controller functions with proper typing using the generated schema types.

### 3. Runtime Validation

`express-openapi-validator` middleware validates all incoming requests and outgoing responses against your OpenAPI specification at runtime.

### 4. Type-Safe Handlers

Controller functions use helper types (`ApiRequest<T>`, `ApiResponse<T>`) that extract the correct types for path params, query params, request body, and response body for each operation.

### 5. Docker Deployment

Multi-stage Dockerfile compiles TypeScript in a builder stage, then creates a minimal production image with only compiled code and production dependencies.

## Type Safety Example

```typescript
import { ApiRequest, ApiResponse } from '../types/api-helpers.js';

// Fully typed request and response based on OpenAPI operation
export const getUserById = async (
  req: ApiRequest<'getUserById'>,
  res: ApiResponse<'getUserById'>,
) => {
  const userId = req.params.id; // Type: string (from path params)

  // Response type matches OpenAPI schema
  res.status(200).json({
    id: userId,
    name: 'John Doe',
    email: 'john@example.com',
  });
};
```

## Troubleshooting

### Port Already in Use

If port 3000 is already in use:

1. Stop the conflicting service
2. Or change the port in `.env` and `docker-compose.yml`

### Docker Build Fails

Ensure you have enough disk space and Docker is running:

```bash
docker system prune  # Clean up unused Docker resources
```

### Type Errors After Updating OpenAPI

Regenerate types and controllers:

```bash
npm run generate
npm run type-check
```

## Contributing

This is a proof-of-concept starter template. Feel free to customize the code generation scripts, add additional automation, or extend the functionality.

## License

MIT
