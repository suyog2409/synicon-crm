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

app.use(express.json());

app.use(
  express.static(
    path.join(__dirname, '..', 'client')
  )
);


// =====================================================
// SESSION / AUTH HELPERS
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

  if (!token) {
    return false;
  }

  const parts = token.split('.');

  if (parts.length !== 2) {
    return false;
  }

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

  if (!validSignature) {
    return false;
  }

  try {

    const data = JSON.parse(
      Buffer.from(payload, 'base64url').toString()
    );

    // Session expires after 7 days
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

  if (!header) {
    return {};
  }

  const cookies = {};

  header.split(';').forEach(cookie => {

    const index = cookie.indexOf('=');

    if (index === -1) {
      return;
    }

    const key = cookie
      .slice(0, index)
      .trim();

    const value = cookie
      .slice(index + 1)
      .trim();

    cookies[key] = decodeURIComponent(value);

  });

  return cookies;
}


// =====================================================
// AUTH MIDDLEWARE
// =====================================================

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
// CHECK LOGIN
// =====================================================

app.get('/api/auth/check', (req, res) => {

  const cookies = parseCookies(req);

  const loggedIn = verifySessionToken(
    cookies[SESSION_COOKIE]
  );

  res.json({
    authenticated: loggedIn
  });

});


// =====================================================
// DATABASE INITIALIZATION
// =====================================================

async function initDatabase() {

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


  // ===================================================
  // FOLLOW-UP COLUMNS
  // ===================================================

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS follow_up_date DATE;
  `);

  await pool.query(`
    ALTER TABLE leads
    ADD COLUMN IF NOT EXISTS follow_up_note TEXT;
  `);


  console.log(
    'Supabase PostgreSQL tables are ready.'
  );

}


// =====================================================
// HEALTH CHECK
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

          (SELECT COUNT(*)
           FROM leads) AS total_leads,

          (SELECT COUNT(*)
           FROM clients) AS total_clients,

          (SELECT COUNT(*)
           FROM projects
           WHERE status = 'IN_PROGRESS')
           AS active_projects,

          (SELECT COALESCE(
            SUM(grand_total), 0
          )
           FROM invoices
           WHERE status != 'CANCELLED')
           AS total_revenue,

          (SELECT COUNT(*)
           FROM leads
           WHERE status = 'FOLLOW_UP')
           AS follow_up_leads

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


// GET LEADS

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


// ADD LEAD

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


      if (
        !name ||
        !phone ||
        !service
      ) {

        return res.status(400).json({
          error:
            'Name, phone and service are required.'
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
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9
        )

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


// EDIT LEAD

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


      if (
        !name ||
        !phone ||
        !service
      ) {

        return res.status(400).json({
          error:
            'Name, phone and service are required.'
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


// DELETE LEAD

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
        message:
          'Lead deleted successfully.'
      });

    } catch (err) {

      res.status(500).json({
        error: err.message
      });

    }

  }
);


// =====================================================
// CONVERT LEAD -> CLIENT
// =====================================================

app.post(
  '/api/leads/:id/convert',
  requireAuth,
  async (req, res) => {

    const client = await pool.connect();

    try {

      await client.query('BEGIN');


      const leadResult = await client.query(
        'SELECT * FROM leads WHERE id = $1',
        [req.params.id]
      );


      if (!leadResult.rows.length) {

        await client.query('ROLLBACK');

        return res.status(404).json({
          error: 'Lead not found'
        });

      }


      const lead = leadResult.rows[0];


      const clientResult = await client.query(`

        INSERT INTO clients
        (
          name,
          company,
          phone,
          email
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4
        )

        RETURNING id

      `, [

        lead.name,

        lead.company,

        lead.phone,

        lead.email

      ]);


      await client.query(`

        UPDATE leads

        SET status = 'WON'

        WHERE id = $1

      `, [

        req.params.id

      ]);


      await client.query('COMMIT');


      res.json({

        success: true,

        clientId:
          clientResult.rows[0].id

      });

    } catch (err) {

      await client.query('ROLLBACK');

      res.status(500).json({
        error: err.message
      });

    } finally {

      client.release();

    }

  }
);


// =====================================================
// CLIENTS
// =====================================================


// GET CLIENTS

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


// ADD CLIENT

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
          error:
            'Name and phone are required.'
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
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7
        )

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


// EDIT CLIENT

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
          error:
            'Name and phone are required.'
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


// DELETE CLIENT

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
        message:
          'Client deleted successfully.'
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


// GET PROJECTS

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


// ADD PROJECT

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
        deadline
      } = req.body;


      if (
        !title ||
        !client_name ||
        !deadline
      ) {

        return res.status(400).json({
          error:
            'Project, client and deadline are required.'
        });

      }


      const { rows } = await pool.query(`

        INSERT INTO projects
        (
          title,
          client_name,
          service,
          budget,
          deadline
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5
        )

        RETURNING *

      `, [

        title,

        client_name,

        service || null,

        Number(budget) || 0,

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


// EDIT PROJECT

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


      if (
        !title ||
        !client_name ||
        !deadline
      ) {

        return res.status(400).json({
          error:
            'Project, client and deadline are required.'
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


// DELETE PROJECT

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
        message:
          'Project deleted successfully.'
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
// GST IS NOT USED
// =====================================================


// GET INVOICES

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


// ADD INVOICE

app.post(
  '/api/invoices',
  requireAuth,
  async (req, res) => {

    try {

      const {
        client_name,
        taxable_amount,
        status,
        date
      } = req.body;


      const amount =
        Number(taxable_amount) || 0;


      if (
        !client_name ||
        amount <= 0
      ) {

        return res.status(400).json({
          error:
            'Client name and amount are required.'
        });

      }


      // GST disabled
      const gstRate = 0;

      const totalTax = 0;

      const grandTotal = amount;


      const invoiceNumber =
        'INV-' +
        Date.now()
          .toString()
          .slice(-8);


      const today =
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
          date
        )

        VALUES
        (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8
        )

        RETURNING *

      `, [

        invoiceNumber,

        client_name,

        amount,

        gstRate,

        totalTax,

        grandTotal,

        status || 'PENDING',

        today

      ]);


      res.status(201).json(rows[0]);

    } catch (err) {

      if (err.code === '23505') {

        return res.status(409).json({
          error:
            'Invoice number already exists. Please try again.'
        });

      }


      res.status(500).json({
        error: err.message
      });

    }

  }
);


// EDIT INVOICE

app.put(
  '/api/invoices/:id',
  requireAuth,
  async (req, res) => {

    try {

      const {
        client_name,
        taxable_amount,
        status,
        date
      } = req.body;


      const amount =
        Number(taxable_amount) || 0;


      if (
        !client_name ||
        amount <= 0
      ) {

        return res.status(400).json({
          error:
            'Client name and amount are required.'
        });

      }


      // GST disabled
      const gstRate = 0;

      const totalTax = 0;

      const grandTotal = amount;


      const { rows } = await pool.query(`

        UPDATE invoices

        SET

          client_name = $1,

          taxable_amount = $2,

          gst_rate = $3,

          total_tax = $4,

          grand_total = $5,

          status = $6,

          date = $7

        WHERE id = $8

        RETURNING *

      `, [

        client_name,

        amount,

        gstRate,

        totalTax,

        grandTotal,

        status || 'PENDING',

        date || null,

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


// DELETE INVOICE

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
        message:
          'Invoice deleted successfully.'
      });

    } catch (err) {

      res.status(500).json({
        error: err.message
      });

    }

  }
);


// =====================================================
// FOLLOW-UP LIST
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
