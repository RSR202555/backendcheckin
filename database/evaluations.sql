DROP TABLE IF EXISTS evaluations;

CREATE TABLE evaluations (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id UUID NOT NULL,
  professional_id UUID NULL,
  appointment_id UUID NULL,
  evaluation_date DATE NOT NULL DEFAULT (CURRENT_DATE),
  pdf_url VARCHAR(500) NULL,
  notes TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT fk_evaluations_client
    FOREIGN KEY (client_id) REFERENCES profiles(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_evaluations_professional
    FOREIGN KEY (professional_id) REFERENCES profiles(id)
    ON DELETE SET NULL,
  CONSTRAINT fk_evaluations_appointment
    FOREIGN KEY (appointment_id) REFERENCES appointments(id)
    ON DELETE SET NULL
);

CREATE INDEX idx_evaluations_client ON evaluations(client_id);
CREATE INDEX idx_evaluations_professional ON evaluations(professional_id);
CREATE INDEX idx_evaluations_appointment ON evaluations(appointment_id);
CREATE INDEX idx_evaluations_date ON evaluations(evaluation_date);
