DROP TABLE IF EXISTS profiles;

CREATE TABLE profiles (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) NOT NULL UNIQUE,
  full_name VARCHAR(255) NOT NULL,
  phone VARCHAR(20) NULL,
  role TEXT NOT NULL DEFAULT 'client' CHECK (role IN ('client','professional','admin')),
  password_hash VARCHAR(255) NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
