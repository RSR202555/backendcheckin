DROP TABLE IF EXISTS appointments;

CREATE TABLE appointments (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id UUID NULL,
  service_id UUID NOT NULL,
  professional_id UUID NULL,
  appointment_date DATE NOT NULL,
  appointment_time TIME NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','confirmed','completed','cancelled')),
  notes TEXT NULL,
  contact_name VARCHAR(255) NULL,
  contact_phone VARCHAR(20) NULL,
  contact_email VARCHAR(255) NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT fk_appointments_client
    FOREIGN KEY (client_id) REFERENCES profiles(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_appointments_service
    FOREIGN KEY (service_id) REFERENCES services(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_appointments_professional
    FOREIGN KEY (professional_id) REFERENCES profiles(id)
    ON DELETE SET NULL
);

CREATE INDEX idx_appointments_client ON appointments(client_id);
CREATE INDEX idx_appointments_service ON appointments(service_id);
CREATE INDEX idx_appointments_professional ON appointments(professional_id);
CREATE INDEX idx_appointments_date_time ON appointments(appointment_date, appointment_time);
