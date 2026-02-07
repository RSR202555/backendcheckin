import { put } from '@vercel/blob';
import type { Request, Response } from 'express';
import pool from './db';

interface MulterRequest extends Request {
  file?: Express.Multer.File;
  body: any;
}

export async function uploadEvaluationWithBlob(req: MulterRequest, res: Response) {
  try {
    const { client_id, professional_id, appointment_id, evaluation_date, notes } = req.body;

    const normalizedAppointmentId = appointment_id === '' || appointment_id === undefined ? null : appointment_id;

    if (!client_id || !professional_id || !evaluation_date) {
      return res.status(400).json({ error: 'Campos obrigatórios ausentes' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Arquivo PDF é obrigatório' });
    }

    // Upload para Vercel Blob
    const filename = `evaluations/${Date.now()}-${req.file.originalname}`;

    const blob = await put(filename, req.file.buffer, {
      access: 'public',
      contentType: 'application/pdf',
    });

    // Salvar no banco com a URL do Blob
    await pool.query(
      'INSERT INTO evaluations (id, client_id, professional_id, appointment_id, evaluation_date, pdf_url, notes) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)',
      [client_id, professional_id, normalizedAppointmentId, evaluation_date, blob.url, notes ?? null]
    );

    res.status(201).json({ success: true, pdf_url: blob.url });
  } catch (error) {
    console.error('Error uploading evaluation to Blob', error);
    res.status(500).json({ error: 'Erro ao fazer upload da avaliação' });
  }
}
