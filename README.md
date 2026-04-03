# Solstice Proxy Detection API

A Node.js API using TypeScript, Express, and Prisma ORM that analyzes whether a requested domain is being accessed through an interception proxy or MITM proxy.

## Prerequisites

- Node.js 18+
- PostgreSQL 14+
- npm or yarn

## Setup

### 1. Database Setup

Install PostgreSQL and create a database:

```bash
# On Windows (using Chocolatey)
choco install postgresql

# On macOS (using Homebrew)
brew install postgresql
brew services start postgresql

# On Ubuntu/Debian
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql
```

Create the database:

```sql
CREATE DATABASE solstice;
CREATE USER solstice_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE solstice TO solstice_user;
```

### 2. Environment Configuration

Update `.env` with your database credentials:

```env
DATABASE_URL="postgresql://solstice_user:your_password@localhost:5432/solstice"
PORT=3000
LICENSE_SECRET="your-secret-key"
```

### 3. Installation and Setup

Run the setup script:

```bash
# Windows
scripts\setup.bat

# Linux/macOS
bash scripts/setup.sh
```

Or manually:

```bash
npm install
npx prisma generate
npx prisma migrate dev --name init
npm run db:seed
```

## Running

```bash
npm run dev
```

The server will start on port 3000 by default.

## API Endpoint

### GET /v1/solstice/check/<base64domain>

Analyzes a domain for proxy interception using behavioral and statistical analysis with authentication.

#### Headers Required:
- `X-API-Key`: Your API key
- `X-Student-Email`: Student email (.edu or .k12.*.us)
- `X-License`: Valid license key

#### Example Request
```bash
# Encode domain as base64
echo -n "gmail.com" | base64  # Outputs: Z21haWwuY29t

curl -X GET "http://localhost:3000/v1/solstice/check/Z21haWwuY29t" \
  -H "X-API-Key: SOLSTICE-DEV-API-KEY-12345" \
  -H "X-Student-Email: student@university.edu" \
  -H "X-License: SOLSTICE-A1B2-C3D4-E5F6"
```

#### Response Format
```json
{
  "site": "gmail.com",
  "status": "unblocked",
  "response": "48.50ms"
}
```

## Database Schema

The system uses Prisma ORM with PostgreSQL:

- **ApiKey**: API key management
- **License**: License validation with expiration
- **StudentEmail**: Approved student email addresses
- **CheckLog**: Audit log of all proxy checks

## Detection Methodology

The API uses behavioral analysis rather than hardcoded rules:

1. **TLS Certificate Analysis**: Computes SHA-256 fingerprints across multiple connections
2. **Timing Analysis**: Measures handshake times and request latency variance
3. **Header Entropy**: Calculates statistical entropy of response headers
4. **Response Consistency**: Compares response body hashes across requests
5. **WebSocket Testing**: Attempts WebSocket upgrades to detect interception
6. **Domain Analysis**: Analyzes domain patterns for proxy indicators
7. **Anomaly Scoring**: Dynamically computes scores based on behavioral patterns

The system avoids false positives from legitimate services by focusing on statistical anomalies rather than fixed patterns.

## Default Credentials

After running the seed script:

- **API Key**: `SOLSTICE-DEV-API-KEY-12345`
- **License**: `SOLSTICE-A1B2-C3D4-E5F6`
- **Student Email**: `student@university.edu`

## Scripts

- `npm run dev`: Start development server
- `npm run build`: Build for production
- `npm run db:generate`: Generate Prisma client
- `npm run db:migrate`: Run database migrations
- `npm run db:seed`: Seed database with sample data
