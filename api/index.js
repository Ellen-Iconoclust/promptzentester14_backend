const { Pool } = require('pg');
const crypto = require('crypto');

// Neon PostgreSQL Configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// Test connection on startup
const initializeDatabase = async () => {
  try {
    const client = await pool.connect();
    console.log('✅ Connected to Neon PostgreSQL database');
    client.release();
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    setTimeout(initializeDatabase, 5000);
  }
};

initializeDatabase();

// Database helper functions (maintaining same interface)
const dbRun = async (sql, params = []) => {
  try {
    const result = await pool.query(sql, params);
    return {
      lastID: result.rows[0]?.id || result.rows[result.rowCount - 1]?.id,
      changes: result.rowCount,
      insertId: result.rows[0]?.id
    };
  } catch (error) {
    console.error('Database run error:', error);
    throw error;
  }
};

const dbGet = async (sql, params = []) => {
  try {
    const result = await pool.query(sql, params);
    return result.rows[0] || null;
  } catch (error) {
    console.error('Database get error:', error);
    throw error;
  }
};

const dbAll = async (sql, params = []) => {
  try {
    const result = await pool.query(sql, params);
    return result.rows;
  } catch (error) {
    console.error('Database all error:', error);
    throw error;
  }
};

// CORS headers
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-requested-with',
};

module.exports = async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(200, corsHeaders);
    return res.end();
  }

  // Set CORS headers for all responses
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    console.log(`Incoming request: ${req.method} ${path}`);
    
    // Route handling - EXACTLY THE SAME STRUCTURE
    if (req.method === 'POST' && path === '/api/register') {
      return await handleRegister(req, res);
    } else if (req.method === 'POST' && path === '/api/login') {
      return await handleLogin(req, res);
    } else if (req.method === 'GET' && path === '/api/prompts') {
      return await handleGetPrompts(req, res);
    } else if (req.method === 'GET' && path === '/api/prompts/pending') {
      return await handleGetPendingPrompts(req, res);
    } else if (req.method === 'POST' && path === '/api/prompts') {
      return await handleCreatePrompt(req, res);
    } else if (req.method === 'POST' && path === '/api/upload') {
      return await handleFileUpload(req, res);
    } else if (req.method === 'PUT' && path.startsWith('/api/prompts/')) {
      return await handleUpdatePrompt(req, res);
    } else if (req.method === 'DELETE' && path.startsWith('/api/prompts/')) {
      return await handleDeletePrompt(req, res);
    } else if (req.method === 'GET' && path === '/api/admin/stats') {
      return await handleAdminStats(req, res);
    } else if (req.method === 'GET' && path === '/api/stats') {
      return await handlePublicStats(req, res);
    } else if (req.method === 'POST' && path === '/api/admin/prompts/bulk-action') {
      return await handleBulkAction(req, res);
    } else if (req.method === 'GET' && path === '/') {
      return res.status(200).json({ 
        message: 'PromptZen API is running with Neon PostgreSQL!', 
        status: 'success',
        database: 'neon-postgresql'
      });
    } else {
      return res.status(404).json({ error: 'Route not found' });
    }
  } catch (error) {
    console.error('Server error:', error);
    return res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
};

// JWT implementation (UNCHANGED)
const jwt = {
  sign: (payload, secret) => {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const encodedPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const signature = crypto
      .createHmac('sha256', secret)
      .update(`${encodedHeader}.${encodedPayload}`)
      .digest('base64url');
    return `${encodedHeader}.${encodedPayload}.${signature}`;
  },
  verify: (token, secret) => {
    try {
      const [encodedHeader, encodedPayload, signature] = token.split('.');
      const expectedSignature = crypto
        .createHmac('sha256', secret)
        .update(`${encodedHeader}.${encodedPayload}`)
        .digest('base64url');
      
      if (signature !== expectedSignature) {
        throw new Error('Invalid token signature');
      }
      
      return JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
    } catch (error) {
      throw new Error('Invalid token');
    }
  }
};

const JWT_SECRET = process.env.JWT_SECRET || '484848484848484848484848484848484848484884848swkjhdjwbjhjdh3djbjd3484848484848484';

// Password hashing (UNCHANGED)
const hashPassword = (password) => {
  return crypto.createHash('sha256').update(password).digest('hex');
};

// Auth middleware (UNCHANGED)
const authenticateToken = (req) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('No token provided');
  }
  
  const token = authHeader.split(' ')[1];
  return jwt.verify(token, JWT_SECRET);
};

// Route handlers (MINIMAL CHANGES FOR PostgreSQL SYNTAX)
async function handleRegister(req, res) {
  try {
    const { username, password } = await parseBody(req);
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Validate username
    if (!username.match(/^[a-zA-Z0-9]{3,20}$/)) {
      return res.status(400).json({ error: 'Username must be 3-20 alphanumeric characters' });
    }
    
    // Validate password
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if user exists
    const existingUser = await dbGet('SELECT * FROM users WHERE username = $1', [username]);
    
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Create user
    const hashedPassword = hashPassword(password);
    const result = await dbRun(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id',
      [username, hashedPassword, 'user']
    );
    
    // Create token
    const token = jwt.sign(
      { username: username, role: 'user' },
      JWT_SECRET
    );
    
    console.log(`User registered successfully: ${username}`);
    
    return res.status(201).json({
      access_token: token,
      username: username,
      role: 'user',
      message: 'Registration successful'
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Registration failed: ' + error.message });
  }
}

async function handleLogin(req, res) {
  try {
    const { username, password } = await parseBody(req);
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    console.log(`Login attempt for user: ${username}`);
    
    // Get user
    const user = await dbGet('SELECT * FROM users WHERE username = $1', [username]);
    
    if (!user) {
      console.log('User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const hashedPassword = hashPassword(password);
    const isPasswordValid = (hashedPassword === user.password);
    
    console.log('Password check:', { 
      username, 
      providedHash: hashedPassword, 
      storedHash: user.password,
      isValid: isPasswordValid 
    });
    
    if (!isPasswordValid) {
      console.log('Password mismatch for user:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Create token
    const token = jwt.sign(
      { username: user.username, role: user.role },
      JWT_SECRET
    );
    
    console.log(`Login successful for user: ${username}, role: ${user.role}`);
    
    return res.json({
      access_token: token,
      username: user.username,
      role: user.role,
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Login failed: ' + error.message });
  }
}

async function handleFileUpload(req, res) {
  try {
    const user = authenticateToken(req);
    
    const body = await parseBody(req);
    const { file: base64File, filename, filetype } = body;
    
    if (!base64File || !filename) {
      return res.status(400).json({ error: 'File data required' });
    }
    
    // Remove data URL prefix if present
    const base64Data = base64File.replace(/^data:image\/\w+;base64,/, '');
    
    // Validate file size (5MB limit)
    if (base64Data.length > 7 * 1024 * 1024) {
      return res.status(400).json({ error: 'File size must be less than 5MB' });
    }
    
    // Generate unique filename
    const fileExt = filename.split('.').pop() || 'jpg';
    const uniqueFilename = `${user.username}_${Date.now()}.${fileExt}`;
    
    return res.json({
      url: `data:${filetype || 'image/jpeg'};base64,${base64Data}`,
      filename: uniqueFilename,
      message: 'File processed successfully'
    });
    
  } catch (error) {
    console.error('File upload error:', error);
    if (error.message === 'Invalid token') {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.status(500).json({ error: 'File upload failed: ' + error.message });
  }
}

async function handleGetPrompts(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const publicOnly = url.searchParams.get('public') !== 'false';
    
    let query = 'SELECT * FROM prompts';
    let params = [];
    
    if (publicOnly) {
      query += ' WHERE accepted = $1';
      params.push(true);
    }
    
    query += ' ORDER BY created_at DESC';
    
    const prompts = await dbAll(query, params);
    
    // Convert for frontend
    const processedPrompts = prompts.map(prompt => ({
      ...prompt,
      image_url: prompt.image_data || null,
      accepted: Boolean(prompt.accepted),
      isTrending: Boolean(prompt.isTrending)
    }));
    
    return res.json(processedPrompts);
  } catch (error) {
    console.error('Error fetching prompts:', error);
    return res.status(500).json({ error: 'Failed to fetch prompts' });
  }
}

async function handleGetPendingPrompts(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const prompts = await dbAll(
      'SELECT * FROM prompts WHERE accepted = $1 ORDER BY created_at DESC',
      [false]
    );
    
    // Convert for frontend
    const processedPrompts = prompts.map(prompt => ({
      ...prompt,
      image_url: prompt.image_data || null,
      accepted: Boolean(prompt.accepted),
      isTrending: Boolean(prompt.isTrending)
    }));
    
    return res.json(processedPrompts);
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handleCreatePrompt(req, res) {
  try {
    const user = authenticateToken(req);
    const body = await parseBody(req);
    
    const { title, tagline, model, text, image_url } = body;
    
    if (!title || !tagline || !model || !text) {
      return res.status(422).json({ error: 'All fields are required' });
    }
    
    // Store image as base64 in database
    const imageData = image_url || null;
    
    console.log('Creating prompt for user:', user.username);
    console.log('Prompt data:', { title, tagline, model });
    
    const result = await dbRun(
      `INSERT INTO prompts (username, title, tagline, model, text, image_data, accepted, "isTrending") 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [user.username, title, tagline, model, text, imageData, user.role === 'admin', false]
    );
    
    console.log('Insert result:', result);
    
    if (!result || !result.lastID) {
      throw new Error('Failed to get prompt ID after insertion');
    }
    
    // Get the created prompt
    const newPrompt = await dbGet('SELECT * FROM prompts WHERE id = $1', [result.lastID]);
    
    if (!newPrompt) {
      throw new Error('Failed to retrieve created prompt');
    }
    
    // Convert for response
    const processedPrompt = {
      ...newPrompt,
      image_url: newPrompt.image_data || null,
      accepted: Boolean(newPrompt.accepted),
      isTrending: Boolean(newPrompt.isTrending)
    };
    
    console.log('Created prompt successfully:', processedPrompt.id);
    
    return res.status(201).json(processedPrompt);
  } catch (error) {
    console.error('Create prompt error:', error);
    if (error.message === 'Invalid token' || error.message === 'No token provided') {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.status(500).json({ error: 'Failed to create prompt: ' + error.message });
  }
}

async function handleUpdatePrompt(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const promptId = req.url.split('/').pop();
    const updates = await parseBody(req);
    
    // Build update query dynamically
    const updateFields = [];
    const updateValues = [];
    let paramCount = 1;
    
    Object.keys(updates).forEach(key => {
      if (key === 'accepted' || key === 'isTrending') {
        updateFields.push(`${key} = $${paramCount}`);
        updateValues.push(updates[key]);
        paramCount++;
      } else if (key !== 'id') {
        updateFields.push(`${key} = $${paramCount}`);
        updateValues.push(updates[key]);
        paramCount++;
      }
    });
    
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    updateValues.push(promptId);
    
    await dbRun(
      `UPDATE prompts SET ${updateFields.join(', ')} WHERE id = $${paramCount}`,
      updateValues
    );
    
    const updatedPrompt = await dbGet('SELECT * FROM prompts WHERE id = $1', [promptId]);
    
    if (!updatedPrompt) {
      return res.status(404).json({ error: 'Prompt not found' });
    }
    
    // Convert for response
    const processedPrompt = {
      ...updatedPrompt,
      image_url: updatedPrompt.image_data || null,
      accepted: Boolean(updatedPrompt.accepted),
      isTrending: Boolean(updatedPrompt.isTrending)
    };
    
    return res.json(processedPrompt);
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handleDeletePrompt(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const promptId = req.url.split('/').pop();
    
    await dbRun('DELETE FROM prompts WHERE id = $1', [promptId]);
    
    return res.json({ message: 'Prompt deleted successfully' });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handleAdminStats(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const prompts = await dbAll('SELECT * FROM prompts');
    const users = await dbAll('SELECT username FROM users');
    
    const totalPrompts = prompts.length;
    const acceptedPrompts = prompts.filter(p => p.accepted).length;
    const pendingPrompts = prompts.filter(p => !p.accepted).length;
    const trendingPrompts = prompts.filter(p => p.isTrending && p.accepted).length;
    const totalUsers = new Set(prompts.map(p => p.username)).size;
    
    return res.json({
      total_prompts: totalPrompts,
      accepted_prompts: acceptedPrompts,
      pending_prompts: pendingPrompts,
      trending_prompts: trendingPrompts,
      total_users: totalUsers
    });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

async function handlePublicStats(req, res) {
  try {
    const prompts = await dbAll('SELECT * FROM prompts WHERE accepted = $1', [true]);
    
    const acceptedPrompts = prompts || [];
    const uniqueUsers = new Set(acceptedPrompts.map(p => p.username));
    const trendingPrompts = acceptedPrompts.filter(p => p.isTrending);
    
    return res.json({
      total_prompts: acceptedPrompts.length,
      total_users: uniqueUsers.size,
      trending_prompts: trendingPrompts.length,
      categories: 0
    });
  } catch (error) {
    console.error('Error fetching public stats:', error);
    return res.status(500).json({ error: 'Failed to fetch stats' });
  }
}

async function handleBulkAction(req, res) {
  try {
    const user = authenticateToken(req);
    
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    
    const { prompt_ids, action } = await parseBody(req);
    
    if (!prompt_ids || !Array.isArray(prompt_ids) || !['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    
    let result;
    if (action === 'approve') {
      result = await dbRun(
        'UPDATE prompts SET accepted = $1 WHERE id = ANY($2)',
        [true, prompt_ids]
      );
    } else if (action === 'reject') {
      result = await dbRun(
        'DELETE FROM prompts WHERE id = ANY($1)',
        [prompt_ids]
      );
    }
    
    return res.json({
      message: `Successfully ${action}d ${prompt_ids.length} prompts`,
      updated_count: prompt_ids.length
    });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Helper function to parse request body (UNCHANGED)
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (error) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}
