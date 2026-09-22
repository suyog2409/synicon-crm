# SYNICON IT SOLUTIONS — CRM

Supabase PostgreSQL version of the SYNICON Mini ERP/CRM.

## Structure

- `server/server.js` — Express API + PostgreSQL/Supabase connection
- `server/package.json` — backend dependencies
- `client/index.html` — CRM frontend
- `package.json` — Render/root start configuration
- `.env.example` — environment variable example

## Render environment variable

Set:

`DATABASE_URL`

to the **Supabase Transaction Pooler URI**. Keep the password private and never commit it to GitHub.

## Run locally

```bash
npm install
npm start
```

Then open:

`http://localhost:5000`

## Database

The server creates the four required tables if they do not already exist:
`leads`, `clients`, `projects`, `invoices`.
