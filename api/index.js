const { createClient } = require('@libsql/client');
const crypto = require('crypto');

// Turso database configuration
const tursoConfig = {
  url: process.env.TURSO_DATABASE_URL || 'libsql://your-database.turso.io',
  authToken: process.env.TURSO_AUTH_TOKEN || 'your-auth-token',
};

// Initialize Turso client
let db;
try {
  db = createClient({
    url: tursoConfig.url,
    authToken: tursoConfig.authToken,
  });
  console.log('Connected to Turso database');
} catch (error) {
  console.error('Turso connection error:', error);
}

// Initialize database tables
async function initializeDatabase() {
  try {
    // Users table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Prompts table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS prompts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        title TEXT NOT NULL,
        tagline TEXT NOT NULL,
        model TEXT NOT NULL,
        text TEXT NOT NULL,
        image_data TEXT,
        image_filename TEXT,
        image_type TEXT,
        accepted BOOLEAN DEFAULT 0,
        isTrending BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Check if we need to insert default data
    const existingUsers = await db.execute('SELECT COUNT(*) as count FROM users');
    if (existingUsers.rows[0].count === 0) {
      console.log('Initializing database with default data...');
      
      // Insert default admin user
      const adminPasswordHash = crypto.createHash('sha256').update('admin123').digest('hex');
      await db.execute({
        sql: 'INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)',
        args: ['admin', adminPasswordHash, 'admin']
      });

      // Insert sample prompts
      const samplePrompts = [
        {
          username: 'admin',
          title: 'Cyberpunk Cityscape',
          tagline: 'Futuristic neon-lit urban environment',
          model: 'Midjourney',
          text: 'Create a cyberpunk cityscape at night with neon lights, flying cars, and towering skyscrapers. Use vibrant colors like electric blue, hot pink, and neon green. Style: cinematic, detailed, 8k resolution --ar 16:9',
          image_data: 'https://images.unsplash.com/photo-1487958449943-2429e8be8625?w=400&h=300&fit=crop',
          accepted: 1,
          isTrending: 1
        },
        {
          username: 'admin',
          title: 'Fantasy Dragon',
          tagline: 'Majestic dragon in mystical landscape',
          model: 'DALL-E',
          text: 'A majestic dragon with iridescent scales flying over a mystical landscape with floating islands and waterfalls. Epic fantasy style, highly detailed, dramatic lighting --ar 3:2',
          image_data: 'https://images.unsplash.com/photo-1518709268805-4e9042af2176?w=400&h=300&fit=crop',
          accepted: 1,
          isTrending: 1
        }
      ];

      for (const prompt of samplePrompts) {
        await db.execute({
          sql: `INSERT OR IGNORE INTO prompts (username, title, tagline, model, text, image_data, accepted, isTrending) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          args: [prompt.username, prompt.title, prompt.tagline, prompt.model, prompt.text, 
                 prompt.image_data, prompt.accepted, prompt.isTrending]
        });
      }

      console.log('Database initialized with admin user: admin / admin123 and sample prompts');
    } else {
      console.log('Using existing database with persistent data');
    }
  } catch (error) {
    console.error('Database initialization error:', error);
  }
}

// Initialize database on startup
initializeDatabase();

// Database helper functions
const dbExecute = db.execute.bind(db);
const dbGet = async (sql, args = []) => {
  const result = await db.execute({ sql, args });
  return result.rows[0] || null;
};
const dbAll = async (sql, args = []) => {
  const result = await db.execute({ sql, args });
  return result.rows;
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
    // Better path parsing for Vercel
    const url = new URL(req.url, `http://${req.headers.host}`);
    const path = url.pathname;
    console.log(`Incoming request: ${req.method} ${path}`);
    
    // Route handling
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
        message: 'PromptZen API is running!', 
        status: 'success',
        database: 'turso'
      });
    } else {
      return res.status(404).json({ error: 'Route not found' });
    }
  } catch (error) {
    console.error('Server error:', error);
    return res.status(500).json({ error: 'Internal server error: ' + error.message });
  }
};

// JWT implementation
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

// Password hashing
const hashPassword = (password) => {
  return crypto.createHash('sha256').update(password).digest('hex');
};

// Auth middleware
const authenticateToken = (req) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('No token provided');
  }
  
  const token = authHeader.split(' ')[1];
  return jwt.verify(token, JWT_SECRET);
};

// Route handlers
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
    const existingUser = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
    
    if (existingUser) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Create user
    const hashedPassword = hashPassword(password);
    await dbExecute({
      sql: 'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      args: [username, hashedPassword, 'user']
    });
    
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
    const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
    
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
    let args = [];
    
    if (publicOnly) {
      query += ' WHERE accepted = ?';
      args.push(1);
    }
    
    query += ' ORDER BY created_at DESC';
    
    const result = await dbExecute({ sql: query, args });
    const prompts = result.rows;
    
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
    
    const result = await dbExecute({
      sql: 'SELECT * FROM prompts WHERE accepted = ? ORDER BY created_at DESC',
      args: [0]
    });
    const prompts = result.rows;
    
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
    
    const result = await dbExecute({
      sql: `INSERT INTO prompts (username, title, tagline, model, text, image_data, accepted, isTrending) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      args: [user.username, title, tagline, model, text, imageData, user.role === 'admin' ? 1 : 0, 0]
    });
    
    // Get the created prompt (Turso doesn't return lastID directly, so we query for it)
    const lastInsertResult = await dbExecute('SELECT last_insert_rowid() as id');
    const promptId = lastInsertResult.rows[0].id;
    
    const newPrompt = await dbGet('SELECT * FROM prompts WHERE id = ?', [promptId]);
    
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
    
    Object.keys(updates).forEach(key => {
      if (key === 'accepted' || key === 'isTrending') {
        updateFields.push(`${key} = ?`);
        updateValues.push(updates[key] ? 1 : 0);
      } else if (key !== 'id') {
        updateFields.push(`${key} = ?`);
        updateValues.push(updates[key]);
      }
    });
    
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }
    
    updateValues.push(promptId);
    
    await dbExecute({
      sql: `UPDATE prompts SET ${updateFields.join(', ')} WHERE id = ?`,
      args: updateValues
    });
    
    const updatedPrompt = await dbGet('SELECT * FROM prompts WHERE id = ?', [promptId]);
    
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
    
    await dbExecute({
      sql: 'DELETE FROM prompts WHERE id = ?',
      args: [promptId]
    });
    
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
    
    const promptsResult = await dbExecute('SELECT * FROM prompts');
    const prompts = promptsResult.rows;
    const usersResult = await dbExecute('SELECT username FROM users');
    const users = usersResult.rows;
    
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
    const result = await dbExecute({
      sql: 'SELECT * FROM prompts WHERE accepted = ?',
      args: [1]
    });
    const prompts = result.rows;
    
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
    
    if (action === 'approve') {
      await dbExecute({
        sql: 'UPDATE prompts SET accepted = ? WHERE id IN (' + prompt_ids.map(() => '?').join(',') + ')',
        args: [1, ...prompt_ids]
      });
    } else if (action === 'reject') {
      await dbExecute({
        sql: 'DELETE FROM prompts WHERE id IN (' + prompt_ids.map(() => '?').join(',') + ')',
        args: prompt_ids
      });
    }
    
    return res.json({
      message: `Successfully ${action}d ${prompt_ids.length} prompts`,
      updated_count: prompt_ids.length
    });
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Helper function to parse request body
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
