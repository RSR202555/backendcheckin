DROP TABLE IF EXISTS appointments;

CREATE TABLE appointments (
  id CHAR(36) NOT NULL PRIMARY KEY DEFAULT (UUID()),
  client_id CHAR(36) NOT NULL,
  service_id CHAR(36) NOT NULL,
  professional_id CHAR(36) NULL,
  appointment_date DATE NOT NULL,
  appointment_time TIME NOT NULL,
  status ENUM('pending','confirmed','completed','cancelled') NOT NULL DEFAULT 'pending',
  notes TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT fk_appointments_client
    FOREIGN KEY (client_id) REFERENCES profiles(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_appointments_service
    FOREIGN KEY (service_id) REFERENCES services(id)
    ON DELETE CASCADE,
  CONSTRAINT fk_appointments_professional
    FOREIGN KEY (professional_id) REFERENCES profiles(id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE INDEX idx_appointments_client ON appointments(client_id);
CREATE INDEX idx_appointments_service ON appointments(service_id);
CREATE INDEX idx_appointments_professional ON appointments(professional_id);
CREATE INDEX idx_appointments_date_time ON appointments(appointment_date, appointment_time);
