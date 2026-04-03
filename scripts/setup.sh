#!/bin/bash

echo "Setting up Solstice Proxy Detection System..."

# Install dependencies
echo "Installing dependencies..."
npm install

# Install Prisma CLI
echo "Installing Prisma CLI..."
npm install -g prisma

# Generate Prisma client
echo "Generating Prisma client..."
npx prisma generate

# Create initial database migration
echo "Creating database migration..."
npx prisma migrate dev --name init

# Seed database with sample data
echo "Seeding database..."
npx prisma db seed

echo "Setup complete!"
echo "To start the server: npm run dev"
