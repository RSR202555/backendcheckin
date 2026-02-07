// Vercel Serverless Entry Point
import app from '../src/index';
import type { VercelRequest, VercelResponse } from '@vercel/node';

// Para desenvolvimento: exporta o app diretamente
export default app;

// Para Vercel serverless: exporta handler
export const handler = (req: VercelRequest, res: VercelResponse) => {
  return app(req as any, res as any);
};
