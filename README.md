# Hitaishi CRM MySQL Backend

This backend connects the Expo app to MySQL through an Express API.

## Setup

1. Create a MySQL database named `hitaishi`.
2. Update `.env` with your MySQL credentials:

```env
PORT=4000
DB_TYPE=MySQL
DB_HOST=209.182.233.18
DB_PORT=3306
DB_USER=hitaishi
DB_NAME=hitaishi
DB_PASSWORD=your_password
```

3. Install and run:

```bash
npm install
npm run migrate
npm run ensure-admin   # seed admin login: admin / admin123 (idempotent)
npm run dev
```

Default **Admin panel** credentials (stored in `users` table):

- **Login ID:** `admin` (stored as `email` column)
- **Password:** `admin123`

Health check:

```text
http://localhost:4000/health
```

## Main Tables

- `users`
- `dealers`
- `customers`
- `technicians`
- `products`
- `serial_numbers`
- `warranties`
- `complaints`
- `tasks`
- `quotations`
- `payments`
- `attachments`
- `feedback`
