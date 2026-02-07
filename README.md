# Clínica Checkin - Backend API

Backend Node.js + TypeScript + PostgreSQL para sistema de agendamento de clínica.

## 🚀 Deploy na Vercel

Este projeto está configurado para deploy automático na **Vercel**.

### Pré-requisitos

1. **Banco PostgreSQL (Neon)** - Gratuito em [neon.tech](https://neon.tech)
2. **Conta Vercel** - Gratuita em [vercel.com](https://vercel.com)

### Passos para Deploy

#### 1. Configurar Banco Neon (se ainda não tiver)

1. Acesse https://neon.tech e crie conta
2. **New Project**
   - Nome: `clinica-checkin`
   - Region: **South America (São Paulo)**
3. Copie a **DATABASE_URL** (Connection String)

#### 2. Deploy na Vercel

1. Acesse https://vercel.com/new
2. **Import Git Repository** → Selecione este repositório
3. **Configure Project:**
   - Framework Preset: **Other**
   - Build Command: `npm run build`
   - Output Directory: `dist`
   - Install Command: `npm install`

#### 3. Configurar Variáveis de Ambiente

No painel da Vercel, adicione as seguintes variáveis:

```
DATABASE_URL=postgresql://user:password@host.neon.tech/dbname?sslmode=require
JWT_SECRET=seu-jwt-secret-min-32-caracteres-aqui
FRONTEND_URL=https://clinicacheckin.com
NODE_ENV=production
```

**Opcional (para email):**
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=seu-email@gmail.com
SMTP_PASSWORD=sua-senha-de-app
SMTP_FROM=seu-email@gmail.com
```

#### 4. Deploy!

- Clique em **Deploy**
- Aguarde ~2 minutos
- Sua API estará em: `https://seu-projeto.vercel.app`

#### 5. Testar

Acesse: `https://seu-projeto.vercel.app/health`

Deve retornar: `{"status":"ok"}` ✅

---

## 🛠️ Desenvolvimento Local

```bash
# Instalar dependências
npm install

# Copiar .env.example para .env
cp .env.example .env

# Editar .env com suas credenciais

# Rodar em dev
npm run dev
```

Acesse: http://localhost:4000

---

## 📦 Build

```bash
npm run build
npm start
```

---

## ⚠️ Upload de Arquivos

**IMPORTANTE:** O upload de PDFs (avaliações) NÃO funciona diretamente na Vercel porque ela é **stateless**.

Para upload de arquivos, você precisa usar um storage externo:
- **Vercel Blob** (pago - R$ 0,15/GB)
- **Cloudinary** (gratuito até 25 GB)
- **AWS S3** (pago)

Por enquanto, a rota `/admin/evaluations/upload` vai retornar erro em produção.

---

## 🔗 URLs

- **Frontend**: https://clinicacheckin.com
- **Backend**: https://seu-backend.vercel.app

---

## 📚 API Endpoints

### Public
- `GET /` - Health check
- `GET /health` - Health check
- `GET /services` - Listar serviços
- `POST /appointments` - Criar agendamento (sem login)
- `GET /appointments/unavailable?date=YYYY-MM-DD` - Horários indisponíveis
- `POST /auth/login` - Login
- `POST /auth/forgot-password` - Solicitar reset de senha
- `POST /auth/reset-password` - Resetar senha com token

### Auth Required
- `GET /auth/me` - Perfil do usuário
- `POST /auth/change-password` - Trocar senha
- `PATCH /profile` - Atualizar perfil

### Client
- `GET /client/:clientId/appointments` - Meus agendamentos
- `GET /client/:clientId/evaluations` - Minhas avaliações

### Admin Only
- `POST /auth/signup` - Criar novo usuário
- `GET /admin/appointments` - Listar todos agendamentos
- `PATCH /admin/appointments/:id/status` - Atualizar status
- `GET /admin/clients` - Listar clientes
- `GET /admin/clients/:clientId/evaluations` - Avaliações de um cliente
- `POST /admin/evaluations` - Criar avaliação
- `DELETE /admin/evaluations/:id` - Deletar avaliação
- `GET /admin/evaluations/latest` - Última avaliação
- `GET /admin/schedule-blocks` - Listar bloqueios
- `POST /admin/schedule-blocks` - Criar bloqueio
- `DELETE /admin/schedule-blocks/:id` - Remover bloqueio

---

## 🎉 Pronto!

Seu backend está no ar! 🚀
