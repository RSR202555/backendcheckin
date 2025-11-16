DROP TABLE IF EXISTS evaluations;

CREATE TABLE evaluations (
  id CHAR(36) NOT NULL PRIMARY KEY DEFAULT (UUID()),
  client_id CHAR(36) NOT NULL,
  professional_id CHAR(36) NULL,
  appointment_id CHAR(36) NULL,
  evaluation_date DATE NOT NULL DEFAULT (CURRENT_DATE),
  pdf_url VARCHAR(500) NULL,
  notes TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT fk_evaluations_client
    FOREIGN KEY (client_id) REFERENCES profiles(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_evaluations_professional
    FOREIGN KEY (professional_id) REFERENCES profiles(id)
    ON DELETE SET NULL,
  CONSTRAINT fk_evaluations_appointment
    FOREIGN KEY (appointment_id) REFERENCES appointments(id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_evaluations_client ON evaluations(client_id);
CREATE INDEX idx_evaluations_professional ON evaluations(professional_id);
CREATE INDEX idx_evaluations_appointment ON evaluations(appointment_id);
CREATE INDEX idx_evaluations_date ON evaluations(evaluation_date);
