CREATE TABLE IF NOT EXISTS users (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  role ENUM('Admin', 'Front Desk', 'Dispatch', 'Dealer', 'Technician', 'Customer') NOT NULL,
  name VARCHAR(160) NOT NULL,
  mobile VARCHAR(30) NOT NULL UNIQUE,
  email VARCHAR(190),
  password_hash VARCHAR(128),
  status VARCHAR(40) NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS dealers (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  user_id CHAR(36),
  dealer_no VARCHAR(60) NOT NULL UNIQUE,
  name VARCHAR(180) NOT NULL,
  contact_person VARCHAR(160),
  mobile VARCHAR(30) NOT NULL,
  address TEXT,
  city VARCHAR(120),
  state VARCHAR(120),
  status VARCHAR(40) NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customers (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  user_id CHAR(36),
  name VARCHAR(160) NOT NULL,
  mobile VARCHAR(30) NOT NULL UNIQUE,
  address TEXT,
  city VARCHAR(120),
  village VARCHAR(120),
  state VARCHAR(120),
  pincode VARCHAR(20),
  created_by_dealer_id CHAR(36),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_customers_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_customers_created_by_dealer FOREIGN KEY (created_by_dealer_id) REFERENCES dealers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS technicians (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  user_id CHAR(36),
  name VARCHAR(160) NOT NULL,
  mobile VARCHAR(30) NOT NULL UNIQUE,
  city VARCHAR(120),
  pincode VARCHAR(20),
  service_areas TEXT,
  approval_status VARCHAR(40) NOT NULL DEFAULT 'Pending',
  created_by_dealer_id CHAR(36),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_technicians_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
  CONSTRAINT fk_technicians_created_by_dealer FOREIGN KEY (created_by_dealer_id) REFERENCES dealers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS product_categories (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  name VARCHAR(120) NOT NULL UNIQUE,
  model_prefix VARCHAR(100) NOT NULL DEFAULT '',
  model_number_width INT NOT NULL DEFAULT 1,
  model_start_number BIGINT NOT NULL DEFAULT 1,
  next_model_number BIGINT NOT NULL,
  serial_prefix VARCHAR(100) NOT NULL DEFAULT '',
  serial_number_width INT NOT NULL DEFAULT 1,
  serial_start_number BIGINT NOT NULL DEFAULT 1,
  next_serial_number BIGINT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS products (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  name VARCHAR(180) NOT NULL,
  model_no VARCHAR(120) NOT NULL,
  category VARCHAR(120),
  category_id CHAR(36) NULL,
  warranty_months INT NOT NULL DEFAULT 12,
  installation_required TINYINT(1) NOT NULL DEFAULT 0,
  qr_status VARCHAR(40) NOT NULL DEFAULT 'Not Printed',
  qr_payload VARCHAR(255),
  qr_printed_at TIMESTAMP NULL,
  qr_locked TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS service_areas (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  state VARCHAR(120),
  city VARCHAR(120) NOT NULL,
  area VARCHAR(160) NOT NULL,
  pincode VARCHAR(20),
  front_desk_user_id CHAR(36),
  status VARCHAR(40) NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_service_areas_area (area),
  INDEX idx_service_areas_pincode (pincode),
  CONSTRAINT fk_service_areas_front_desk FOREIGN KEY (front_desk_user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS work_type_costs (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  work_type VARCHAR(120) NOT NULL,
  product_category VARCHAR(120),
  model_no VARCHAR(120),
  city VARCHAR(120),
  technician_id CHAR(36),
  payable_amount DECIMAL(10, 2) NOT NULL DEFAULT 0,
  service_charge DECIMAL(10, 2) NOT NULL DEFAULT 0,
  visit_charge DECIMAL(10, 2) NOT NULL DEFAULT 0,
  tax_amount DECIMAL(10, 2) NOT NULL DEFAULT 0,
  discount_amount DECIMAL(10, 2) NOT NULL DEFAULT 0,
  default_timeframe_hours INT NOT NULL DEFAULT 24,
  effective_date DATE,
  status VARCHAR(40) NOT NULL DEFAULT 'Active',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_work_type_costs_work_type (work_type),
  CONSTRAINT fk_work_type_costs_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS serial_numbers (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  product_id CHAR(36),
  dealer_id CHAR(36),
  serial_no VARCHAR(120) NOT NULL UNIQUE,
  invoice_no VARCHAR(120),
  challan_no VARCHAR(120),
  batch_no VARCHAR(120),
  dispatch_date DATE,
  qr_status VARCHAR(40) NOT NULL DEFAULT 'Not Printed',
  qr_payload VARCHAR(255),
  qr_printed_at TIMESTAMP NULL,
  dispatch_status VARCHAR(40) NOT NULL DEFAULT 'Pending',
  dispatched_at TIMESTAMP NULL,
  installation_required TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_serial_numbers_serial_no (serial_no),
  INDEX idx_serial_numbers_batch_no (batch_no),
  CONSTRAINT fk_serials_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
  CONSTRAINT fk_serials_dealer FOREIGN KEY (dealer_id) REFERENCES dealers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS warranties (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  warranty_no VARCHAR(80) NOT NULL UNIQUE,
  customer_id CHAR(36),
  dealer_id CHAR(36),
  serial_id CHAR(36),
  start_date DATE,
  expiry_date DATE,
  status VARCHAR(60) NOT NULL DEFAULT 'Pending Verification',
  installation_status VARCHAR(60) NOT NULL DEFAULT 'Required',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_warranties_customer_id (customer_id),
  CONSTRAINT fk_warranties_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
  CONSTRAINT fk_warranties_dealer FOREIGN KEY (dealer_id) REFERENCES dealers(id) ON DELETE SET NULL,
  CONSTRAINT fk_warranties_serial FOREIGN KEY (serial_id) REFERENCES serial_numbers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS complaints (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  complaint_no VARCHAR(80) NOT NULL UNIQUE,
  warranty_id CHAR(36),
  customer_id CHAR(36),
  dealer_id CHAR(36),
  problem_type VARCHAR(160) NOT NULL,
  description TEXT,
  priority VARCHAR(40) NOT NULL DEFAULT 'Normal',
  product_name VARCHAR(160),
  model_no VARCHAR(120),
  warranty_start_date DATE,
  warranty_end_date DATE,
  warranty_status VARCHAR(60),
  status VARCHAR(40) NOT NULL DEFAULT 'Open',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_complaints_customer_id (customer_id),
  INDEX idx_complaints_dealer_id (dealer_id),
  CONSTRAINT fk_complaints_warranty FOREIGN KEY (warranty_id) REFERENCES warranties(id) ON DELETE SET NULL,
  CONSTRAINT fk_complaints_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
  CONSTRAINT fk_complaints_dealer FOREIGN KEY (dealer_id) REFERENCES dealers(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tasks (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  task_no VARCHAR(80) NOT NULL UNIQUE,
  complaint_id CHAR(36),
  technician_id CHAR(36),
  work_type VARCHAR(120) NOT NULL,
  due_at TIMESTAMP NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'Assigned',
  completed_at TIMESTAMP NULL,
  resolution_notes TEXT,
  payable_amount DECIMAL(10, 2) DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_tasks_technician_id (technician_id),
  CONSTRAINT fk_tasks_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE SET NULL,
  CONSTRAINT fk_tasks_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS quotations (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  quotation_no VARCHAR(80) NOT NULL UNIQUE,
  complaint_id CHAR(36),
  technician_id CHAR(36),
  spare_part_amount DECIMAL(10, 2) DEFAULT 0,
  service_charge DECIMAL(10, 2) DEFAULT 0,
  visit_charge DECIMAL(10, 2) DEFAULT 0,
  tax_amount DECIMAL(10, 2) DEFAULT 0,
  discount_amount DECIMAL(10, 2) DEFAULT 0,
  total_amount DECIMAL(10, 2) DEFAULT 0,
  technician_remarks TEXT,
  customer_remarks TEXT,
  customer_decided_at TIMESTAMP NULL,
  frontdesk_instruction VARCHAR(40),
  frontdesk_instructed_at TIMESTAMP NULL,
  customer_payment_status VARCHAR(40) NOT NULL DEFAULT 'Pending',
  customer_paid_at TIMESTAMP NULL,
  sent_to_frontdesk_at TIMESTAMP NULL,
  status VARCHAR(60) NOT NULL DEFAULT 'Pending Customer Approval',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_quotations_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
  CONSTRAINT fk_quotations_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notifications (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  recipient_role VARCHAR(80),
  customer_id CHAR(36),
  user_id CHAR(36),
  type VARCHAR(80) NOT NULL,
  title VARCHAR(180) NOT NULL,
  message TEXT,
  entity_type VARCHAR(80),
  entity_id CHAR(36),
  read_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_notifications_customer (customer_id),
  INDEX idx_notifications_user (user_id),
  INDEX idx_notifications_role (recipient_role),
  INDEX idx_notifications_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS status_history (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  complaint_id CHAR(36),
  old_status VARCHAR(80),
  new_status VARCHAR(80) NOT NULL,
  changed_by_role VARCHAR(80),
  changed_by_id CHAR(36),
  remarks TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_status_history_complaint (complaint_id),
  INDEX idx_status_history_created (created_at),
  CONSTRAINT fk_status_history_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS complaint_assignments (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  complaint_id CHAR(36) NOT NULL,
  technician_id CHAR(36) NOT NULL,
  assigned_by_role VARCHAR(80),
  assigned_by_id CHAR(36),
  assigned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status VARCHAR(40) NOT NULL DEFAULT 'Assigned',
  remarks TEXT,
  INDEX idx_complaint_assignments_complaint (complaint_id),
  CONSTRAINT fk_complaint_assignments_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
  CONSTRAINT fk_complaint_assignments_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS messages_or_comments (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  complaint_id CHAR(36),
  quotation_id CHAR(36),
  sender_role VARCHAR(80),
  sender_id CHAR(36),
  receiver_role VARCHAR(80),
  receiver_id CHAR(36),
  message TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_messages_complaint (complaint_id),
  INDEX idx_messages_quotation (quotation_id),
  INDEX idx_messages_created (created_at),
  CONSTRAINT fk_messages_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
  CONSTRAINT fk_messages_quotation FOREIGN KEY (quotation_id) REFERENCES quotations(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS payments (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  technician_id CHAR(36),
  task_id CHAR(36),
  amount DECIMAL(10, 2) NOT NULL,
  status VARCHAR(40) NOT NULL DEFAULT 'Pending',
  paid_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_payments_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE CASCADE,
  CONSTRAINT fk_payments_task FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS attachments (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  entity_type VARCHAR(80) NOT NULL,
  entity_id CHAR(36) NOT NULL,
  file_url TEXT NOT NULL,
  file_type VARCHAR(80),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS feedback (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  complaint_id CHAR(36),
  customer_id CHAR(36),
  technician_id CHAR(36),
  rating INT NOT NULL,
  remarks TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_feedback_complaint (complaint_id),
  CONSTRAINT chk_feedback_rating CHECK (rating BETWEEN 1 AND 5),
  CONSTRAINT fk_feedback_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
  CONSTRAINT fk_feedback_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE CASCADE,
  CONSTRAINT fk_feedback_technician FOREIGN KEY (technician_id) REFERENCES technicians(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS replace_return_cases (
  id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
  case_no VARCHAR(80) NOT NULL UNIQUE,
  complaint_id CHAR(36) NOT NULL,
  task_id CHAR(36),
  warranty_id CHAR(36),
  customer_id CHAR(36),
  dealer_id CHAR(36) NOT NULL,
  serial_id CHAR(36),
  action_type VARCHAR(40) NOT NULL,
  problem_details TEXT NOT NULL,
  technician_remarks TEXT,
  status VARCHAR(60) NOT NULL DEFAULT 'Pending Admin Scan',
  qr_status VARCHAR(40) NOT NULL DEFAULT 'Not Printed',
  qr_payload VARCHAR(255),
  qr_printed_at TIMESTAMP NULL,
  admin_scanned_at TIMESTAMP NULL,
  admin_scanned_by CHAR(36),
  replacement_serial_id CHAR(36),
  replacement_dispatched_at TIMESTAMP NULL,
  replacement_dispatched_by CHAR(36),
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_rr_dealer (dealer_id),
  INDEX idx_rr_status (status),
  INDEX idx_rr_complaint (complaint_id),
  CONSTRAINT fk_rr_complaint FOREIGN KEY (complaint_id) REFERENCES complaints(id) ON DELETE CASCADE,
  CONSTRAINT fk_rr_task FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE SET NULL,
  CONSTRAINT fk_rr_warranty FOREIGN KEY (warranty_id) REFERENCES warranties(id) ON DELETE SET NULL,
  CONSTRAINT fk_rr_customer FOREIGN KEY (customer_id) REFERENCES customers(id) ON DELETE SET NULL,
  CONSTRAINT fk_rr_dealer FOREIGN KEY (dealer_id) REFERENCES dealers(id) ON DELETE CASCADE,
  CONSTRAINT fk_rr_serial FOREIGN KEY (serial_id) REFERENCES serial_numbers(id) ON DELETE SET NULL,
  CONSTRAINT fk_rr_admin_user FOREIGN KEY (admin_scanned_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
