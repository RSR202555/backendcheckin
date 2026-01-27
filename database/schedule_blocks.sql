DROP TABLE IF EXISTS schedule_blocks;

CREATE TABLE schedule_blocks (
  id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  block_date DATE NOT NULL,
  block_time TIME NULL,
  reason TEXT NULL,
  created_by UUID NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT fk_schedule_blocks_created_by FOREIGN KEY (created_by) REFERENCES profiles(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX uniq_schedule_blocks_date_null_time ON schedule_blocks(block_date) WHERE block_time IS NULL;
CREATE UNIQUE INDEX uniq_schedule_blocks_date_time ON schedule_blocks(block_date, block_time) WHERE block_time IS NOT NULL;
