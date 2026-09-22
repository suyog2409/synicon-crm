const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 5000;

// =====================================================
// ENVIRONMENT
// =====================================================

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL environment variable is missing.');
  process.exit(1);
}

if (!process.env.ADMIN_USERNAME) {
  console.error('ERROR: ADMIN_USERNAME environment variable is missing.');
  process.exit(1);
}

if (!process.env.ADMIN_PASSWORD) {
  console.error('ERROR: ADMIN_PASSWORD environment variable is missing.');
  process.exit(1);
}

if (!process.env.SESSION_SECRET) {
  console.error('ERROR: SESSION_SECRET environment variable is missing.');
  process.exit(1);
}

// =====================================================
// DATABASE
// =====================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

// =====================================================
// APP
// =====================================================

app.use(cors({
  origin: true,
  credentials: true
}));

app.use(express.json({ limit: '2mb' }));

app.use(
  express.static(
    path.join(__dirname, '..', 'client')
  )
);

// =====================================================
// AUTH / SESSION
// =====================================================

const SESSION_COOKIE = 'synicon_session';

function createSessionToken() {
  const payload = {
    username: process.env.ADMIN_USERNAME,
    createdAt: Date.now()
  };

  const encodedPayload = Buffer
    .from(JSON.stringify(payload))
    .toString('base64url');

  const signature = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(encodedPayload)
    .digest('base64url');

  return `${encodedPayload}.${signature}`;
}

function verifySessionToken(token) {
  if (!token) return false;

  const parts = token.split('.');

  if (parts.length !== 2) return false;

  const [payload, signature] = parts;

  const expectedSignature = crypto
    .createHmac('sha256', process.env.SESSION_SECRET)
    .update(payload)
    .digest('base64url');

  if (signature.length !== expectedSignature.length) {
    return false;
  }

  const validSignature = crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expectedSignature)
  );

  if (!validSignature) return false;

  try {
    const data = JSON.parse(
      Buffer.from(payload, 'base64url').toString()
    );

    const maxAge = 7 * 24 * 60 * 60 * 1000;

    if (
      !data.createdAt ||
      Date.now() - data.createdAt > maxAge
    ) {
      return false;
    }

    return data.username === process.env.ADMIN_USERNAME;

  } catch (err) {
    return false;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie;

  if (!header) return {};

  const cookies = {};

  header.split(';').forEach(cookie => {
    const index = cookie.indexOf('=');

    if (index === -1) return;

    const key = cookie
      .slice(0, index)
      .trim();

    const value = cookie
      .slice(index + 1)
      .trim();

    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
  });

  return cookies;
}

function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies[SESSION_COOKIE];

  if (!verifySessionToken(token)) {
    return res.status(401).json({
      error: 'Unauthorized. Please login.'
    });
  }

  next();
}

// =====================================================
// LOGIN
// =====================================================

app.post('/api/login', (req, res) => {
  const {
    username,
    password
  } = req.body;

  if (
    username !== process.env.ADMIN_USERNAME ||
    password !== process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: 'Invalid username or password.'
    });
  }

  const token = createSessionToken();

  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800`
  );

  res.json({
    success: true,
    message: 'Login successful.'
  });
});

// =====================================================
// LOGOUT
// =====================================================

app.post('/api/logout', (req, res) => {
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`
  );

  res.json({
    success: true,
    message: 'Logged out successfully.'
  });
});

// =====================================================
// AUTH CHECK
// =====================================================

app.get('/api/auth/check', (req, res) => {
  const cookies = parseCookies(req);

  res.json({
    authenticated: verifySessionToken(
      cookies[SESSION_COOKIE]
    )
  });
});

// =====================================================
// DATABASE INITIALIZATION
// =====================================================

async function initDatabase() {

  // -----------------------------
  // LEADS
  // -----------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS leads (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      company TEXT,
      phone TEXT NOT NULL,
      email TEXT,
      service TEXT,
      expected_value NUMERIC DEFAULT 0,
      status TEXT DEFAULT 'NEW'
    );
  `);

  // -----------------------------
  // CLIENTS
  // -----------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS clients (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      name TEXT NOT NULL,
      company TEXT,
      phone TEXT NOT NULL,
      email TEXT,
      gstin TEXT,
      state TEXT DEFAULT 'Maharashtra',
      state_code TEXT DEFAULT '27'
    );
  `);

  // -----------------------------
  // PROJECTS
  // -----------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS projects (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      title TEXT NOT NULL,
      client_name TEXT NOT NULL,
      service TEXT,
      budget NUMERIC DEFAULT 0,
      status TEXT DEFAULT 'IN_PROGRESS',
      deadline DATE
    );
  `);

  // -----------------------------
  // INVOICES
  // -----------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS invoices (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      invoice_number TEXT UNIQUE,
      client_name TEXT NOT NULL,
      taxable_amount NUMERIC NOT NULL,
      gst_rate NUMERIC DEFAULT 0,
      total_tax NUMERIC NOT NULL DEFAULT 0,
      grand_total NUMERIC NOT NULL,
      status TEXT DEFAULT 'PENDING',
      date DATE
    );
  `);

  // -----------------------------
  // FOLLOW-UP
  // -----------------------------

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS follow_up_date DATE;
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS follow_up_note TEXT;
  `);

  // -----------------------------
  // INVOICE EXTRA FIELDS
  // -----------------------------

  await pool.query(`
    ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS due_date DATE;
  `);

  await pool.query(`
    ALTER TABLE invoices
    ADD COLUMN IF NOT EXISTS notes TEXT;
  `);

  // -----------------------------
  // PAYMENTS
  // -----------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payments (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      invoice_id BIGINT,
      client_name TEXT NOT NULL,
      amount NUMERIC NOT NULL DEFAULT 0,
      payment_date DATE NOT NULL,
      method TEXT DEFAULT 'CASH',
      reference TEXT,
      note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // -----------------------------
  // EXPENSES
  // -----------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS expenses (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT DEFAULT 'OTHER',
      amount NUMERIC NOT NULL DEFAULT 0,
      expense_date DATE NOT NULL,
      payment_method TEXT DEFAULT 'CASH',
      note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // -----------------------------
  // QUOTATIONS
  // -----------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS quotations (
      id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
      quotation_number TEXT UNIQUE NOT NULL,
      client_name TEXT NOT NULL,
      service TEXT,
      amount NUMERIC NOT NULL DEFAULT 0,
      status TEXT DEFAULT 'DRAFT',
      date DATE NOT NULL,
      valid_until DATE,
      notes TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log('Supabase PostgreSQL tables are ready.');
}

// =====================================================
// HEALTH
// =====================================================

app.get('/api/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      success: true,
      database: 'connected'
    });

  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// =====================================================
// DASHBOARD STATS
// =====================================================

app.get(
  '/api/stats',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT

          (
            SELECT COUNT(*)
            FROM leads
          ) AS total_leads,

          (
            SELECT COUNT(*)
            FROM clients
          ) AS total_clients,

          (
            SELECT COUNT(*)
            FROM projects
            WHERE status = 'IN_PROGRESS'
          ) AS active_projects,

          (
            SELECT COALESCE(SUM(grand_total), 0)
            FROM invoices
            WHERE status != 'CANCELLED'
          ) AS total_revenue,

          (
            SELECT COALESCE(SUM(amount), 0)
            FROM payments
          ) AS total_paid,

          (
            SELECT COALESCE(SUM(amount), 0)
            FROM expenses
          ) AS total_expenses,

          (
            SELECT
              COALESCE(
                SUM(grand_total), 0
              )
            FROM invoices
            WHERE status != 'CANCELLED'
          )
          -
          (
            SELECT COALESCE(SUM(amount), 0)
            FROM payments
          ) AS pending_amount,

          (
            SELECT
              COALESCE(SUM(amount), 0)
              FROM payments
          )
          -
          (
            SELECT
              COALESCE(SUM(amount), 0)
              FROM expenses
          ) AS profit,

          (
            SELECT COUNT(*)
            FROM leads
            WHERE status = 'FOLLOW_UP'
          ) AS follow_up_leads
      `);

      res.json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// LEADS
// =====================================================

// GET
app.get(
  '/api/leads',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT *
        FROM leads
        ORDER BY id DESC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// ADD
app.post(
  '/api/leads',
  requireAuth,
  async (req, res) => {

    try {

      const {
        name,
        company,
        phone,
        email,
        service,
        expected_value,
        status,
        follow_up_date,
        follow_up_note
      } = req.body;

      if (!name || !phone || !service) {
        return res.status(400).json({
          error: 'Name, phone and service are required.'
        });
      }

      const { rows } = await pool.query(`
        INSERT INTO leads
        (
          name,
          company,
          phone,
          email,
          service,
          expected_value,
          status,
          follow_up_date,
          follow_up_note
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        RETURNING *
      `, [
        name,
        company || null,
        phone,
        email || null,
        service,
        Number(expected_value) || 0,
        status || 'NEW',
        follow_up_date || null,
        follow_up_note || null
      ]);

      res.status(201).json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// EDIT
app.put(
  '/api/leads/:id',
  requireAuth,
  async (req, res) => {

    try {

      const {
        name,
        company,
        phone,
        email,
        service,
        expected_value,
        status,
        follow_up_date,
        follow_up_note
      } = req.body;

      if (!name || !phone || !service) {
        return res.status(400).json({
          error: 'Name, phone and service are required.'
        });
      }

      const { rows } = await pool.query(`
        UPDATE leads
        SET
          name = $1,
          company = $2,
          phone = $3,
          email = $4,
          service = $5,
          expected_value = $6,
          status = $7,
          follow_up_date = $8,
          follow_up_note = $9
        WHERE id = $10
        RETURNING *
      `, [
        name,
        company || null,
        phone,
        email || null,
        service,
        Number(expected_value) || 0,
        status || 'NEW',
        follow_up_date || null,
        follow_up_note || null,
        req.params.id
      ]);

      if (!rows.length) {
        return res.status(404).json({
          error: 'Lead not found'
        });
      }

      res.json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// DELETE
app.delete(
  '/api/leads/:id',
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        'DELETE FROM leads WHERE id = $1',
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Lead not found'
        });
      }

      res.json({
        success: true,
        message: 'Lead deleted successfully.'
      });

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// CONVERT LEAD TO CLIENT
// =====================================================

app.post(
  '/api/leads/:id/convert',
  requireAuth,
  async (req, res) => {

    const db = await pool.connect();

    try {

      await db.query('BEGIN');

      const leadResult = await db.query(
        'SELECT * FROM leads WHERE id = $1',
        [req.params.id]
      );

      if (!leadResult.rows.length) {

        await db.query('ROLLBACK');

        return res.status(404).json({
          error: 'Lead not found'
        });
      }

      const lead = leadResult.rows[0];

      const clientResult = await db.query(`
        INSERT INTO clients
        (
          name,
          company,
          phone,
          email
        )
        VALUES
        ($1,$2,$3,$4)
        RETURNING id
      `, [
        lead.name,
        lead.company,
        lead.phone,
        lead.email
      ]);

      await db.query(`
        UPDATE leads
        SET status = 'WON'
        WHERE id = $1
      `, [req.params.id]);

      await db.query('COMMIT');

      res.json({
        success: true,
        clientId: clientResult.rows[0].id
      });

    } catch (err) {

      await db.query('ROLLBACK');

      res.status(500).json({
        error: err.message
      });

    } finally {
      db.release();
    }
  }
);

// =====================================================
// CLIENTS
// =====================================================

// GET
app.get(
  '/api/clients',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT *
        FROM clients
        ORDER BY id DESC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// ADD
app.post(
  '/api/clients',
  requireAuth,
  async (req, res) => {

    try {

      const {
        name,
        company,
        phone,
        email,
        gstin,
        state,
        state_code
      } = req.body;

      if (!name || !phone) {
        return res.status(400).json({
          error: 'Name and phone are required.'
        });
      }

      const { rows } = await pool.query(`
        INSERT INTO clients
        (
          name,
          company,
          phone,
          email,
          gstin,
          state,
          state_code
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7)
        RETURNING *
      `, [
        name,
        company || null,
        phone,
        email || null,
        gstin || null,
        state || 'Maharashtra',
        state_code || '27'
      ]);

      res.status(201).json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// EDIT
app.put(
  '/api/clients/:id',
  requireAuth,
  async (req, res) => {

    try {

      const {
        name,
        company,
        phone,
        email,
        gstin,
        state,
        state_code
      } = req.body;

      if (!name || !phone) {
        return res.status(400).json({
          error: 'Name and phone are required.'
        });
      }

      const { rows } = await pool.query(`
        UPDATE clients
        SET
          name = $1,
          company = $2,
          phone = $3,
          email = $4,
          gstin = $5,
          state = $6,
          state_code = $7
        WHERE id = $8
        RETURNING *
      `, [
        name,
        company || null,
        phone,
        email || null,
        gstin || null,
        state || 'Maharashtra',
        state_code || '27',
        req.params.id
      ]);

      if (!rows.length) {
        return res.status(404).json({
          error: 'Client not found'
        });
      }

      res.json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// DELETE
app.delete(
  '/api/clients/:id',
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        'DELETE FROM clients WHERE id = $1',
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Client not found'
        });
      }

      res.json({
        success: true,
        message: 'Client deleted successfully.'
      });

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// PROJECTS
// =====================================================

// GET
app.get(
  '/api/projects',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT *
        FROM projects
        ORDER BY id DESC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// ADD
app.post(
  '/api/projects',
  requireAuth,
  async (req, res) => {

    try {

      const {
        title,
        client_name,
        service,
        budget,
        status,
        deadline
      } = req.body;

      if (!title || !client_name || !deadline) {
        return res.status(400).json({
          error: 'Project, client and deadline are required.'
        });
      }

      const { rows } = await pool.query(`
        INSERT INTO projects
        (
          title,
          client_name,
          service,
          budget,
          status,
          deadline
        )
        VALUES
        ($1,$2,$3,$4,$5,$6)
        RETURNING *
      `, [
        title,
        client_name,
        service || null,
        Number(budget) || 0,
        status || 'IN_PROGRESS',
        deadline
      ]);

      res.status(201).json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// EDIT
app.put(
  '/api/projects/:id',
  requireAuth,
  async (req, res) => {

    try {

      const {
        title,
        client_name,
        service,
        budget,
        status,
        deadline
      } = req.body;

      if (!title || !client_name || !deadline) {
        return res.status(400).json({
          error: 'Project, client and deadline are required.'
        });
      }

      const { rows } = await pool.query(`
        UPDATE projects
        SET
          title = $1,
          client_name = $2,
          service = $3,
          budget = $4,
          status = $5,
          deadline = $6
        WHERE id = $7
        RETURNING *
      `, [
        title,
        client_name,
        service || null,
        Number(budget) || 0,
        status || 'IN_PROGRESS',
        deadline,
        req.params.id
      ]);

      if (!rows.length) {
        return res.status(404).json({
          error: 'Project not found'
        });
      }

      res.json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// DELETE
app.delete(
  '/api/projects/:id',
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        'DELETE FROM projects WHERE id = $1',
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Project not found'
        });
      }

      res.json({
        success: true,
        message: 'Project deleted successfully.'
      });

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// INVOICES
// GST NOT USED
// =====================================================

function generateInvoiceNumber() {
  const now = new Date();

  const year = now.getFullYear();

  const random = Math.floor(
    100000 + Math.random() * 900000
  );

  return `INV-${year}-${random}`;
}

// GET
app.get(
  '/api/invoices',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT *
        FROM invoices
        ORDER BY id DESC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// ADD
app.post(
  '/api/invoices',
  requireAuth,
  async (req, res) => {

    try {

      const {
        client_name,
        amount,
        taxable_amount,
        status,
        date,
        due_date,
        notes
      } = req.body;

      const invoiceAmount =
        Number(
          amount !== undefined
            ? amount
            : taxable_amount
        ) || 0;

      if (!client_name || invoiceAmount <= 0) {
        return res.status(400).json({
          error: 'Client name and amount are required.'
        });
      }

      // GST intentionally disabled.
      const gstRate = 0;
      const totalTax = 0;
      const grandTotal = invoiceAmount;

      const invoiceNumber =
        generateInvoiceNumber();

      const invoiceDate =
        date ||
        new Date()
          .toISOString()
          .split('T')[0];

      const { rows } = await pool.query(`
        INSERT INTO invoices
        (
          invoice_number,
          client_name,
          taxable_amount,
          gst_rate,
          total_tax,
          grand_total,
          status,
          date,
          due_date,
          notes
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
        RETURNING *
      `, [
        invoiceNumber,
        client_name,
        invoiceAmount,
        gstRate,
        totalTax,
        grandTotal,
        status || 'PENDING',
        invoiceDate,
        due_date || null,
        notes || null
      ]);

      res.status(201).json(rows[0]);

    } catch (err) {

      if (err.code === '23505') {
        return res.status(409).json({
          error: 'Invoice number already exists. Please try again.'
        });
      }

      res.status(500).json({
        error: err.message
      });
    }
  }
);

// EDIT
app.put(
  '/api/invoices/:id',
  requireAuth,
  async (req, res) => {

    try {

      const {
        client_name,
        amount,
        taxable_amount,
        status,
        date,
        due_date,
        notes
      } = req.body;

      const invoiceAmount =
        Number(
          amount !== undefined
            ? amount
            : taxable_amount
        ) || 0;

      if (!client_name || invoiceAmount <= 0) {
        return res.status(400).json({
          error: 'Client name and amount are required.'
        });
      }

      const { rows } = await pool.query(`
        UPDATE invoices
        SET
          client_name = $1,
          taxable_amount = $2,
          gst_rate = 0,
          total_tax = 0,
          grand_total = $3,
          status = $4,
          date = $5,
          due_date = $6,
          notes = $7
        WHERE id = $8
        RETURNING *
      `, [
        client_name,
        invoiceAmount,
        invoiceAmount,
        status || 'PENDING',
        date || null,
        due_date || null,
        notes || null,
        req.params.id
      ]);

      if (!rows.length) {
        return res.status(404).json({
          error: 'Invoice not found'
        });
      }

      res.json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// DELETE
app.delete(
  '/api/invoices/:id',
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        'DELETE FROM invoices WHERE id = $1',
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Invoice not found'
        });
      }

      res.json({
        success: true,
        message: 'Invoice deleted successfully.'
      });

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// FOLLOW-UPS
// =====================================================

app.get(
  '/api/followups',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT *
        FROM leads
        WHERE follow_up_date IS NOT NULL
        ORDER BY follow_up_date ASC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// PAYMENTS
// =====================================================

// GET PAYMENTS
app.get(
  '/api/payments',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT
          p.*,
          i.invoice_number
        FROM payments p
        LEFT JOIN invoices i
          ON i.id = p.invoice_id
        ORDER BY
          p.payment_date DESC,
          p.id DESC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// ADD PAYMENT
app.post(
  '/api/payments',
  requireAuth,
  async (req, res) => {

    const db = await pool.connect();

    try {

      const {
        invoice_id,
        client_name,
        amount,
        payment_date,
        method,
        reference,
        note
      } = req.body;

      const paymentAmount =
        Number(amount) || 0;

      if (
        !client_name ||
        paymentAmount <= 0 ||
        !payment_date
      ) {
        return res.status(400).json({
          error:
            'Client name, amount and payment date are required.'
        });
      }

      await db.query('BEGIN');

      const { rows } = await db.query(`
        INSERT INTO payments
        (
          invoice_id,
          client_name,
          amount,
          payment_date,
          method,
          reference,
          note
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7)
        RETURNING *
      `, [
        invoice_id || null,
        client_name,
        paymentAmount,
        payment_date,
        method || 'CASH',
        reference || null,
        note || null
      ]);

      // Automatically update invoice status.
      if (invoice_id) {

        const invoiceResult =
          await db.query(`
            SELECT grand_total
            FROM invoices
            WHERE id = $1
          `, [invoice_id]);

        if (invoiceResult.rows.length) {

          const paidResult =
            await db.query(`
              SELECT
                COALESCE(SUM(amount),0) AS paid
              FROM payments
              WHERE invoice_id = $1
            `, [invoice_id]);

          const total =
            Number(
              invoiceResult.rows[0].grand_total
            ) || 0;

          const paid =
            Number(
              paidResult.rows[0].paid
            ) || 0;

          let invoiceStatus = 'PARTIAL';

          if (paid >= total && total > 0) {
            invoiceStatus = 'PAID';
          }

          await db.query(`
            UPDATE invoices
            SET status = $1
            WHERE id = $2
          `, [
            invoiceStatus,
            invoice_id
          ]);
        }
      }

      await db.query('COMMIT');

      res.status(201).json(rows[0]);

    } catch (err) {

      await db.query('ROLLBACK');

      res.status(500).json({
        error: err.message
      });

    } finally {
      db.release();
    }
  }
);

// DELETE PAYMENT
app.delete(
  '/api/payments/:id',
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        'DELETE FROM payments WHERE id = $1',
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Payment not found'
        });
      }

      res.json({
        success: true,
        message: 'Payment deleted successfully.'
      });

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// EXPENSES
// =====================================================

// GET
app.get(
  '/api/expenses',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT *
        FROM expenses
        ORDER BY
          expense_date DESC,
          id DESC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// ADD
app.post(
  '/api/expenses',
  requireAuth,
  async (req, res) => {

    try {

      const {
        title,
        category,
        amount,
        expense_date,
        payment_method,
        note
      } = req.body;

      const expenseAmount =
        Number(amount) || 0;

      if (
        !title ||
        expenseAmount <= 0 ||
        !expense_date
      ) {
        return res.status(400).json({
          error:
            'Title, amount and expense date are required.'
        });
      }

      const { rows } = await pool.query(`
        INSERT INTO expenses
        (
          title,
          category,
          amount,
          expense_date,
          payment_method,
          note
        )
        VALUES
        ($1,$2,$3,$4,$5,$6)
        RETURNING *
      `, [
        title,
        category || 'OTHER',
        expenseAmount,
        expense_date,
        payment_method || 'CASH',
        note || null
      ]);

      res.status(201).json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// EDIT
app.put(
  '/api/expenses/:id',
  requireAuth,
  async (req, res) => {

    try {

      const {
        title,
        category,
        amount,
        expense_date,
        payment_method,
        note
      } = req.body;

      const expenseAmount =
        Number(amount) || 0;

      if (
        !title ||
        expenseAmount <= 0 ||
        !expense_date
      ) {
        return res.status(400).json({
          error:
            'Title, amount and expense date are required.'
        });
      }

      const { rows } = await pool.query(`
        UPDATE expenses
        SET
          title = $1,
          category = $2,
          amount = $3,
          expense_date = $4,
          payment_method = $5,
          note = $6
        WHERE id = $7
        RETURNING *
      `, [
        title,
        category || 'OTHER',
        expenseAmount,
        expense_date,
        payment_method || 'CASH',
        note || null,
        req.params.id
      ]);

      if (!rows.length) {
        return res.status(404).json({
          error: 'Expense not found'
        });
      }

      res.json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// DELETE
app.delete(
  '/api/expenses/:id',
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        'DELETE FROM expenses WHERE id = $1',
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Expense not found'
        });
      }

      res.json({
        success: true,
        message: 'Expense deleted successfully.'
      });

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// QUOTATIONS
// =====================================================

async function generateQuotationNumber() {

  const year = new Date().getFullYear();

  const { rows } = await pool.query(`
    SELECT quotation_number
    FROM quotations
    ORDER BY id DESC
    LIMIT 1
  `);

  let nextNumber = 1;

  if (
    rows.length &&
    rows[0].quotation_number
  ) {

    const match =
      rows[0]
        .quotation_number
        .match(/(\d+)$/);

    if (match) {
      nextNumber =
        Number(match[1]) + 1;
    }
  }

  return `QT-${year}-${String(nextNumber).padStart(4, '0')}`;
}

// GET
app.get(
  '/api/quotations',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`
        SELECT *
        FROM quotations
        ORDER BY id DESC
      `);

      res.json(rows);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// ADD
app.post(
  '/api/quotations',
  requireAuth,
  async (req, res) => {

    try {

      const {
        client_name,
        service,
        amount,
        status,
        date,
        valid_until,
        notes
      } = req.body;

      const quotationAmount =
        Number(amount) || 0;

      if (
        !client_name ||
        quotationAmount <= 0 ||
        !date
      ) {
        return res.status(400).json({
          error:
            'Client name, amount and date are required.'
        });
      }

      const quotationNumber =
        await generateQuotationNumber();

      const { rows } = await pool.query(`
        INSERT INTO quotations
        (
          quotation_number,
          client_name,
          service,
          amount,
          status,
          date,
          valid_until,
          notes
        )
        VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8)
        RETURNING *
      `, [
        quotationNumber,
        client_name,
        service || null,
        quotationAmount,
        status || 'DRAFT',
        date,
        valid_until || null,
        notes || null
      ]);

      res.status(201).json(rows[0]);

    } catch (err) {

      if (err.code === '23505') {
        return res.status(409).json({
          error:
            'Quotation number already exists.'
        });
      }

      res.status(500).json({
        error: err.message
      });
    }
  }
);

// EDIT
app.put(
  '/api/quotations/:id',
  requireAuth,
  async (req, res) => {

    try {

      const {
        client_name,
        service,
        amount,
        status,
        date,
        valid_until,
        notes
      } = req.body;

      const quotationAmount =
        Number(amount) || 0;

      if (
        !client_name ||
        quotationAmount <= 0 ||
        !date
      ) {
        return res.status(400).json({
          error:
            'Client name, amount and date are required.'
        });
      }

      const { rows } = await pool.query(`
        UPDATE quotations
        SET
          client_name = $1,
          service = $2,
          amount = $3,
          status = $4,
          date = $5,
          valid_until = $6,
          notes = $7
        WHERE id = $8
        RETURNING *
      `, [
        client_name,
        service || null,
        quotationAmount,
        status || 'DRAFT',
        date,
        valid_until || null,
        notes || null,
        req.params.id
      ]);

      if (!rows.length) {
        return res.status(404).json({
          error: 'Quotation not found'
        });
      }

      res.json(rows[0]);

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// DELETE
app.delete(
  '/api/quotations/:id',
  requireAuth,
  async (req, res) => {

    try {

      const result = await pool.query(
        'DELETE FROM quotations WHERE id = $1',
        [req.params.id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          error: 'Quotation not found'
        });
      }

      res.json({
        success: true,
        message: 'Quotation deleted successfully.'
      });

    } catch (err) {
      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// REPORTS - SUMMARY
// =====================================================

app.get(
  '/api/reports/summary',
  requireAuth,
  async (req, res) => {

    try {

      const [
        invoiceResult,
        paymentResult,
        expenseResult,
        leadResult,
        projectResult
      ] = await Promise.all([

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COALESCE(SUM(grand_total),0) AS total
          FROM invoices
          WHERE status != 'CANCELLED'
        `),

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COALESCE(SUM(amount),0) AS total
          FROM payments
        `),

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COALESCE(SUM(amount),0) AS total
          FROM expenses
        `),

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COUNT(*) FILTER(
              WHERE status = 'WON'
            ) AS won,
            COALESCE(
              SUM(expected_value),0
            ) AS pipeline
          FROM leads
        `),

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COUNT(*) FILTER(
              WHERE status = 'IN_PROGRESS'
            ) AS active,
            COALESCE(
              SUM(budget),0
            ) AS value
          FROM projects
        `)
      ]);

      const billed =
        Number(invoiceResult.rows[0].total) || 0;

      const paid =
        Number(paymentResult.rows[0].total) || 0;

      const expenses =
        Number(expenseResult.rows[0].total) || 0;

      res.json({

        invoices: {
          count:
            Number(
              invoiceResult.rows[0].count
            ) || 0,
          total: billed
        },

        payments: {
          count:
            Number(
              paymentResult.rows[0].count
            ) || 0,
          total: paid
        },

        expenses: {
          count:
            Number(
              expenseResult.rows[0].count
            ) || 0,
          total: expenses
        },

        pending:
          Math.max(
            billed - paid,
            0
          ),

        profit:
          paid - expenses,

        leads: {
          count:
            Number(
              leadResult.rows[0].count
            ) || 0,

          won:
            Number(
              leadResult.rows[0].won
            ) || 0,

          pipeline_value:
            Number(
              leadResult.rows[0].pipeline
            ) || 0
        },

        projects: {
          count:
            Number(
              projectResult.rows[0].count
            ) || 0,

          active:
            Number(
              projectResult.rows[0].active
            ) || 0,

          value:
            Number(
              projectResult.rows[0].value
            ) || 0
        }
      });

    } catch (err) {

      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// CLIENT REPORT
// =====================================================

app.get(
  '/api/reports/client',
  requireAuth,
  async (req, res) => {

    try {

      const clientName =
        String(
          req.query.name || ''
        ).trim();

      if (!clientName) {
        return res.status(400).json({
          error: 'Client name is required.'
        });
      }

      const [
        invoiceResult,
        paymentResult,
        projectResult
      ] = await Promise.all([

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COALESCE(
              SUM(grand_total),0
            ) AS total
          FROM invoices
          WHERE client_name = $1
            AND status != 'CANCELLED'
        `, [clientName]),

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COALESCE(
              SUM(amount),0
            ) AS total
          FROM payments
          WHERE client_name = $1
        `, [clientName]),

        pool.query(`
          SELECT
            COUNT(*) AS count,
            COALESCE(
              SUM(budget),0
            ) AS total
          FROM projects
          WHERE client_name = $1
        `, [clientName])
      ]);

      const billed =
        Number(
          invoiceResult.rows[0].total
        ) || 0;

      const paid =
        Number(
          paymentResult.rows[0].total
        ) || 0;

      res.json({

        client_name: clientName,

        invoices: {
          count:
            Number(
              invoiceResult.rows[0].count
            ) || 0,
          total: billed
        },

        payments: {
          count:
            Number(
              paymentResult.rows[0].count
            ) || 0,
          total: paid
        },

        pending:
          Math.max(
            billed - paid,
            0
          ),

        projects: {
          count:
            Number(
              projectResult.rows[0].count
            ) || 0,

          total:
            Number(
              projectResult.rows[0].total
            ) || 0
        }
      });

    } catch (err) {

      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// MONTHLY REPORT
// =====================================================

app.get(
  '/api/reports/monthly',
  requireAuth,
  async (req, res) => {

    try {

      const { rows } = await pool.query(`

        WITH months AS (

          SELECT generate_series(
            date_trunc(
              'month',
              CURRENT_DATE
            ) - INTERVAL '11 months',

            date_trunc(
              'month',
              CURRENT_DATE
            ),

            INTERVAL '1 month'
          )::date AS month
        ),

        payments_monthly AS (

          SELECT
            date_trunc(
              'month',
              payment_date
            )::date AS month,

            COALESCE(
              SUM(amount),
              0
            ) AS total

          FROM payments

          GROUP BY 1
        ),

        expenses_monthly AS (

          SELECT
            date_trunc(
              'month',
              expense_date
            )::date AS month,

            COALESCE(
              SUM(amount),
              0
            ) AS total

          FROM expenses

          GROUP BY 1
        ),

        invoices_monthly AS (

          SELECT
            date_trunc(
              'month',
              date
            )::date AS month,

            COALESCE(
              SUM(grand_total),
              0
            ) AS total

          FROM invoices

          WHERE status != 'CANCELLED'

          GROUP BY 1
        )

        SELECT

          m.month,

          COALESCE(
            i.total,
            0
          ) AS billed,

          COALESCE(
            p.total,
            0
          ) AS paid,

          COALESCE(
            e.total,
            0
          ) AS expenses,

          COALESCE(
            p.total,
            0
          )
          -
          COALESCE(
            e.total,
            0
          ) AS profit

        FROM months m

        LEFT JOIN invoices_monthly i
          ON i.month = m.month

        LEFT JOIN payments_monthly p
          ON p.month = m.month

        LEFT JOIN expenses_monthly e
          ON e.month = m.month

        ORDER BY m.month ASC

      `);

      res.json(rows);

    } catch (err) {

      res.status(500).json({
        error: err.message
      });
    }
  }
);

// =====================================================
// FRONTEND FALLBACK
// =====================================================

app.get('*', (req, res) => {

  if (req.path.startsWith('/api/')) {
    return res.status(404).json({
      error: 'API route not found'
    });
  }

  res.sendFile(
    path.join(
      __dirname,
      '..',
      'client',
      'index.html'
    )
  );
});

// =====================================================
// START SERVER
// =====================================================

initDatabase()

  .then(() => {

    app.listen(PORT, () => {

      console.log(
        `SYNICON CRM running on port ${PORT}`
      );

    });

  })

  .catch((err) => {

    console.error(
      'Database initialization failed:',
      err
    );

    process.exit(1);

  });
