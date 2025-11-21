import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import type { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer, { FileFilterCallback } from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import pool from './db';

dotenv.config();

const app = express();
const allowedOrigin = process.env.FRONTEND_URL;
if (allowedOrigin) {
  app.use(cors({ origin: allowedOrigin, credentials: false }));
} else {
  app.use(cors());
}
app.use(express.json());

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: Number(process.env.SMTP_PORT || 587) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  },
});

const uploadRoot = path.resolve(__dirname, '..', 'uploads');
const evaluationsUploadDir = path.join(uploadRoot, 'evaluations');

if (!fs.existsSync(evaluationsUploadDir)) {
  fs.mkdirSync(evaluationsUploadDir, { recursive: true });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req: express.Request, _file: Express.Multer.File, cb: (error: Error | null, destination: string) => void) => {
      cb(null, evaluationsUploadDir);
    },
    filename: (_req: express.Request, file: Express.Multer.File, cb: (error: Error | null, filename: string) => void) => {
      const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`;
      const ext = path.extname(file.originalname) || '.pdf';
      cb(null, `${uniqueSuffix}${ext}`);
    },
  }),
  fileFilter: (_req: express.Request, file: Express.Multer.File, cb: FileFilterCallback) => {
    if (file.mimetype !== 'application/pdf') {
      return cb(new Error('Apenas arquivos PDF são permitidos'));
    }
    cb(null, true);
  },
});

app.use('/files', express.static(uploadRoot));

const PORT = process.env.PORT || 4000;
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET não configurado nas variáveis de ambiente');
}
const JWT_SECRET: jwt.Secret = process.env.JWT_SECRET;

interface JwtPayload {
  userId: string;
}

function generateToken(userId: string): string {
  return jwt.sign({ userId } as JwtPayload, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req: Request & { userId?: string }, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token não fornecido' });
  }

  const token = authHeader.substring(7);

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

async function requireAdmin(req: Request & { userId?: string }, res: Response, next: NextFunction) {
  if (!req.userId) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  try {
    const [rows] = await pool.query('SELECT role FROM profiles WHERE id = ? LIMIT 1', [req.userId]);
    const user = (rows as any[])[0];
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Acesso negado' });
    }
    next();
  } catch (error) {
    console.error('Erro ao verificar permissão de admin', error);
    return res.status(500).json({ error: 'Erro de autorização' });
  }
}

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

// Auth - signup (registro) - apenas administradores podem cadastrar novos usuários
app.post('/auth/signup', authMiddleware, requireAdmin, async (req: Request & { userId?: string }, res: Response) => {
  const { email, password, full_name, phone } = req.body as {
    email?: string;
    password?: string;
    full_name?: string;
    phone?: string;
  };

  if (!email || !password || !full_name) {
    return res.status(400).json({ error: 'email, password e full_name são obrigatórios' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT id FROM profiles WHERE email = ? LIMIT 1',
      [email]
    );

    if ((existing as any[]).length > 0) {
      return res.status(409).json({ error: 'E-mail já cadastrado' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO profiles (id, email, full_name, phone, role, password_hash)
       VALUES (UUID(), ?, ?, ?, 'client', ?)`,
      [email, full_name, phone ?? null, passwordHash]
    );

    const [rows] = await pool.query(
      'SELECT id, email, full_name, phone, role, created_at, updated_at FROM profiles WHERE email = ? LIMIT 1',
      [email]
    );

    const profile = (rows as any[])[0];

    // Vincular agendamentos existentes (sem client_id) a este novo cliente com base no e-mail de contato
    if (profile?.id) {
      try {
        await pool.query(
          'UPDATE appointments SET client_id = ? WHERE client_id IS NULL AND contact_email = ?',
          [profile.id, email]
        );
      } catch (linkError) {
        console.error('Erro ao vincular agendamentos existentes ao novo cliente', linkError);
      }
    }
    const token = generateToken(profile.id);

    res.status(201).json({ token, profile });
  } catch (error) {
    console.error('Erro no signup', error);
    res.status(500).json({ error: 'Erro ao registrar usuário' });
  }
});

// Auth - login
app.post('/auth/login', async (req: Request, res: Response) => {
  const { email, password } = req.body as { email?: string; password?: string };

  if (!email || !password) {
    return res.status(400).json({ error: 'email e password são obrigatórios' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, email, full_name, phone, role, created_at, updated_at, password_hash FROM profiles WHERE email = ? LIMIT 1',
      [email]
    );

    const user = (rows as any[])[0];
    if (!user || !user.password_hash) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const { password_hash, ...profile } = user;
    const token = generateToken(profile.id);

    res.json({ token, profile });
  } catch (error) {
    console.error('Erro no login', error);
    res.status(500).json({ error: 'Erro ao autenticar usuário' });
  }
});

// Auth - me (perfil do usuário logado)
app.get('/auth/me', authMiddleware, async (req: Request & { userId?: string }, res: Response) => {
  if (!req.userId) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id, email, full_name, phone, role, created_at, updated_at FROM profiles WHERE id = ? LIMIT 1',
      [req.userId]
    );

    const profile = (rows as any[])[0];
    if (!profile) {
      return res.status(404).json({ error: 'Perfil não encontrado' });
    }

    res.json({ profile });
  } catch (error) {
    console.error('Erro no /auth/me', error);
    res.status(500).json({ error: 'Erro ao buscar perfil' });
  }
});

// Auth - change password
app.post('/auth/change-password', authMiddleware, async (req: Request & { userId?: string }, res: Response) => {
  if (!req.userId) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  const { current_password, new_password } = req.body as { current_password?: string; new_password?: string };

  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'current_password e new_password são obrigatórios' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT password_hash FROM profiles WHERE id = ? LIMIT 1',
      [req.userId]
    );

    const user = (rows as any[])[0];
    if (!user || !user.password_hash) {
      return res.status(400).json({ error: 'Usuário não possui senha cadastrada' });
    }

    const match = await bcrypt.compare(current_password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Senha atual incorreta' });
    }

    const newHash = await bcrypt.hash(new_password, 10);
    await pool.query(
      'UPDATE profiles SET password_hash = ?, updated_at = NOW() WHERE id = ?',
      [newHash, req.userId]
    );

    return res.json({ success: true });
  } catch (error) {
    console.error('Erro ao alterar senha', error);
    return res.status(500).json({ error: 'Erro ao alterar senha' });
  }
});

async function sendPasswordResetEmail(email: string, token: string) {
  const frontendUrl = process.env.FRONTEND_URL || '';
  const resetUrl = `${frontendUrl.replace(/\/$/, '')}/reset-password?token=${token}`;

  const from = process.env.SMTP_FROM || process.env.SMTP_USER;

  await transporter.sendMail({
    from,
    to: email,
    subject: 'Redefinição de senha - Clínica Checkin',
    text: `Você solicitou a redefinição de senha. Acesse o link a seguir para definir uma nova senha: ${resetUrl}

Se você não fez esta solicitação, ignore este e-mail.`,
    html: `<p>Você solicitou a redefinição de senha.</p>
<p>Clique no link abaixo para definir uma nova senha:</p>
<p><a href="${resetUrl}">${resetUrl}</a></p>
<p>Se você não fez esta solicitação, ignore este e-mail.</p>`,
  });
}

// Auth - solicitar reset de senha (gera token e envia e-mail)
app.post('/auth/forgot-password', async (req: Request, res: Response) => {
  const { email } = req.body as { email?: string };

  if (!email) {
    return res.status(400).json({ error: 'email é obrigatório' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT id FROM profiles WHERE email = ? LIMIT 1',
      [email]
    );

    const user = (rows as any[])[0];

    // Responder 200 mesmo se não existir para não vazar se o e-mail está cadastrado
    if (!user) {
      return res.json({ success: true });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

    await pool.query(
      'INSERT INTO password_resets (user_id, token, expires_at, used) VALUES (?, ?, ?, 0)',
      [user.id, token, expiresAt]
    );

    await sendPasswordResetEmail(email, token);

    return res.json({ success: true });
  } catch (error) {
    console.error('Erro ao solicitar redefinição de senha', error);
    return res.status(500).json({ error: 'Erro ao solicitar redefinição de senha' });
  }
});

// Auth - confirmar reset de senha com token
app.post('/auth/reset-password', async (req: Request, res: Response) => {
  const { token, new_password } = req.body as { token?: string; new_password?: string };

  if (!token || !new_password) {
    return res.status(400).json({ error: 'token e new_password são obrigatórios' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT pr.user_id FROM password_resets pr WHERE pr.token = ? AND pr.used = 0 AND pr.expires_at > NOW() LIMIT 1',
      [token]
    );

    const reset = (rows as any[])[0];
    if (!reset) {
      return res.status(400).json({ error: 'Token inválido ou expirado' });
    }

    const newHash = await bcrypt.hash(new_password, 10);

    await pool.query(
      'UPDATE profiles SET password_hash = ?, updated_at = NOW() WHERE id = ?',
      [newHash, reset.user_id]
    );

    await pool.query(
      'UPDATE password_resets SET used = 1, used_at = NOW() WHERE token = ?',
      [token]
    );

    return res.json({ success: true });
  } catch (error) {
    console.error('Erro ao redefinir senha com token', error);
    return res.status(500).json({ error: 'Erro ao redefinir senha' });
  }
});

// Profile - update dados básicos
app.patch('/profile', authMiddleware, async (req: Request & { userId?: string }, res: Response) => {
  if (!req.userId) {
    return res.status(401).json({ error: 'Não autenticado' });
  }

  const { full_name, phone } = req.body as { full_name?: string; phone?: string };

  try {
    await pool.query(
      'UPDATE profiles SET full_name = COALESCE(?, full_name), phone = COALESCE(?, phone), updated_at = NOW() WHERE id = ?',
      [full_name ?? null, phone ?? null, req.userId]
    );

    const [rows] = await pool.query(
      'SELECT id, email, full_name, phone, role, created_at, updated_at FROM profiles WHERE id = ? LIMIT 1',
      [req.userId]
    );

    const profile = (rows as any[])[0];
    res.json({ profile });
  } catch (error) {
    console.error('Erro ao atualizar perfil', error);
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

// Services
app.get('/services', async (_req: Request, res: Response) => {
  try {
    const [rows] = await pool.query(
      'SELECT id, name, description, duration_minutes, price, active, created_at FROM services WHERE active = 1 ORDER BY name ASC'
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching services', error);
    res.status(500).json({ error: 'Erro ao buscar serviços' });
  }
});

// Appointments - criação (sem necessidade de login)
app.post('/appointments', async (req: Request, res: Response) => {
  const { service_id, appointment_date, appointment_time, notes, contact_name, contact_phone } = req.body as {
    service_id?: string;
    appointment_date?: string;
    appointment_time?: string;
    notes?: string | null;
    contact_name?: string;
    contact_phone?: string;
  };

  if (!service_id || !appointment_date || !appointment_time || !contact_name || !contact_phone) {
    return res.status(400).json({ error: 'Campos obrigatórios ausentes' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT id FROM appointments WHERE appointment_date = ? AND appointment_time = ? LIMIT 1',
      [appointment_date, appointment_time]
    );

    if ((existing as any[]).length > 0) {
      return res.status(409).json({ error: 'Já existe um agendamento para esta data e horário.' });
    }

    await pool.query(
      'INSERT INTO appointments (id, client_id, service_id, appointment_date, appointment_time, notes, status, contact_name, contact_phone) VALUES (UUID(), NULL, ?, ?, ?, ?, ?, ?, ?)',
      [service_id, appointment_date, appointment_time, notes ?? null, 'pending', contact_name, contact_phone]
    );
    res.status(201).json({ success: true });
  } catch (error) {
    console.error('Error creating appointment', error);
    res.status(500).json({ error: 'Erro ao criar agendamento' });
  }
});

// Appointments - horários indisponíveis para uma data
app.get('/appointments/unavailable', async (req: Request, res: Response) => {
  const { date } = req.query as { date?: string };

  if (!date) {
    return res.status(400).json({ error: 'Parâmetro date é obrigatório (YYYY-MM-DD)' });
  }

  try {
    const [rows] = await pool.query(
      'SELECT appointment_time FROM appointments WHERE appointment_date = ? AND status <> "cancelled"',
      [date]
    );

    const times = (rows as any[]).map((r) => r.appointment_time);
    res.json(times);
  } catch (error) {
    console.error('Error fetching unavailable appointment times', error);
    res.status(500).json({ error: 'Erro ao buscar horários indisponíveis' });
  }
});

// Admin - appointments with details
app.get('/admin/appointments', authMiddleware, requireAdmin, async (_req: Request, res: Response) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.notes,
        COALESCE(p.full_name, a.contact_name) AS client_full_name,
        p.email AS client_email,
        COALESCE(p.phone, a.contact_phone) AS client_phone,
        s.name AS service_name
      FROM appointments a
      LEFT JOIN profiles p ON a.client_id = p.id
      JOIN services s ON a.service_id = s.id
      ORDER BY a.appointment_date DESC, a.appointment_time DESC
      LIMIT 50`
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching admin appointments', error);
    res.status(500).json({ error: 'Erro ao buscar agendamentos' });
  }
});

// Admin - clients
app.get('/admin/clients', authMiddleware, requireAdmin, async (_req: Request, res: Response) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, full_name, email, phone, created_at
       FROM profiles
       WHERE role = 'client'
       ORDER BY created_at DESC`
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching clients', error);
    res.status(500).json({ error: 'Erro ao buscar clientes' });
  }
});

// Admin - update appointment status
app.patch('/admin/appointments/:id/status', authMiddleware, requireAdmin, async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status } = req.body as { status?: string };

  if (!status) {
    return res.status(400).json({ error: 'Status é obrigatório' });
  }

  try {
    await pool.query('UPDATE appointments SET status = ? WHERE id = ?', [status, id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating appointment status', error);
    res.status(500).json({ error: 'Erro ao atualizar status do agendamento' });
  }
});

// Admin - create evaluation
app.post('/admin/evaluations', authMiddleware, requireAdmin, async (req: Request, res: Response) => {
  const { client_id, professional_id, appointment_id, evaluation_date, pdf_url, notes } = req.body;

  const normalizedAppointmentId = appointment_id === '' || appointment_id === undefined ? null : appointment_id;

  if (!client_id || !professional_id || !evaluation_date) {
    return res.status(400).json({ error: 'Campos obrigatórios ausentes' });
  }

  try {
    await pool.query(
      'INSERT INTO evaluations (id, client_id, professional_id, appointment_id, evaluation_date, pdf_url, notes) VALUES (UUID(), ?, ?, ?, ?, ?, ?)',
      [client_id, professional_id, normalizedAppointmentId, evaluation_date, pdf_url ?? null, notes ?? null]
    );
    res.status(201).json({ success: true });
  } catch (error) {
    console.error('Error creating evaluation', error);
    res.status(500).json({ error: 'Erro ao registrar avaliação' });
  }
});

// Admin - upload evaluation PDF and create evaluation
interface MulterRequest extends Request {
  file?: Express.Multer.File;
}

app.post('/admin/evaluations/upload', authMiddleware, requireAdmin, upload.single('file'), async (req: MulterRequest, res: Response) => {
  try {
    const { client_id, professional_id, appointment_id, evaluation_date, notes } = req.body as {
      client_id?: string;
      professional_id?: string;
      appointment_id?: string;
      evaluation_date?: string;
      notes?: string;
    };

    const normalizedAppointmentId = appointment_id === '' || appointment_id === undefined ? null : appointment_id;

    if (!client_id || !professional_id || !evaluation_date) {
      return res.status(400).json({ error: 'Campos obrigatórios ausentes' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Arquivo PDF é obrigatório' });
    }

    const relativePath = path.join('evaluations', req.file.filename).replace(/\\/g, '/');
    const publicUrl = `/files/${relativePath}`;

    await pool.query(
      'INSERT INTO evaluations (id, client_id, professional_id, appointment_id, evaluation_date, pdf_url, notes) VALUES (UUID(), ?, ?, ?, ?, ?, ?)',
      [client_id, professional_id, normalizedAppointmentId, evaluation_date, publicUrl, notes ?? null]
    );

    res.status(201).json({ success: true, pdf_url: publicUrl });
  } catch (error) {
    console.error('Error uploading evaluation PDF', error);
    res.status(500).json({ error: 'Erro ao fazer upload da avaliação' });
  }
});

// Client - appointments for a given client (somente o próprio usuário)
app.get('/client/:clientId/appointments', authMiddleware, async (req: Request & { userId?: string }, res: Response) => {
  const { clientId } = req.params;

  if (!req.userId || req.userId !== clientId) {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  try {
    const [rows] = await pool.query(
      `SELECT 
        a.id,
        a.appointment_date,
        a.appointment_time,
        a.status,
        a.notes,
        s.name AS service_name,
        s.duration_minutes AS service_duration_minutes
      FROM appointments a
      JOIN services s ON a.service_id = s.id
      WHERE a.client_id = ?
      ORDER BY a.appointment_date DESC, a.appointment_time DESC`,
      [clientId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching client appointments', error);
    res.status(500).json({ error: 'Erro ao buscar agendamentos do cliente' });
  }
});

// Client - evaluations for a given client (somente o próprio usuário)
app.get('/client/:clientId/evaluations', authMiddleware, async (req: Request & { userId?: string }, res: Response) => {
  const { clientId } = req.params;

  if (!req.userId || req.userId !== clientId) {
    return res.status(403).json({ error: 'Acesso negado' });
  }

  try {
    const [rows] = await pool.query(
      `SELECT 
        e.id,
        e.evaluation_date,
        e.pdf_url,
        e.notes,
        p.full_name AS professional_full_name
      FROM evaluations e
      JOIN profiles p ON e.professional_id = p.id
      WHERE e.client_id = ?
      ORDER BY e.evaluation_date DESC`,
      [clientId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching client evaluations', error);
    res.status(500).json({ error: 'Erro ao buscar avaliações do cliente' });
  }
});

// Admin - evaluations history for a given client
app.get('/admin/clients/:clientId/evaluations', authMiddleware, requireAdmin, async (req: Request, res: Response) => {
  const { clientId } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT 
        e.id,
        e.client_id,
        e.professional_id,
        e.evaluation_date,
        e.pdf_url,
        e.notes,
        p.full_name AS professional_full_name
      FROM evaluations e
      JOIN profiles p ON e.professional_id = p.id
      WHERE e.client_id = ?
      ORDER BY e.evaluation_date ASC`,
      [clientId]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching admin client evaluations', error);
    res.status(500).json({ error: 'Erro ao buscar avaliações do cliente para o admin' });
  }
});

// Admin - latest evaluation (for notifications)
app.get('/admin/evaluations/latest', authMiddleware, requireAdmin, async (_req: Request, res: Response) => {
  try {
    const [rows] = await pool.query(
      `SELECT 
        id,
        client_id,
        professional_id,
        appointment_id,
        evaluation_date,
        pdf_url,
        notes,
        created_at
      FROM evaluations
      ORDER BY created_at DESC
      LIMIT 1`
    );

    const evaluations = rows as any[];
    if (evaluations.length === 0) {
      return res.json(null);
    }

    res.json(evaluations[0]);
  } catch (error) {
    console.error('Error fetching latest evaluation', error);
    res.status(500).json({ error: 'Erro ao buscar última avaliação' });
  }
});

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});
