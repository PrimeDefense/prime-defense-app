# Prime Defense Protection Member App

This package includes:

- React front-end member app
- Express backend API
- Stripe membership lookup by email
- Stripe webhook route
- Member lock/unlock logic
- Emergency Mode
- Aftermath Mode
- Emergency contact field
- State-by-state carry guide mock structure

## Important Security Note

Do not paste Stripe secret keys into chat, email, or public files. Add them only inside your hosting provider's private environment-variable settings or your local `.env` file.

## Local Test Setup

1. Open this folder in VS Code or Terminal.
2. Install everything:

```bash
npm install
npm run install-all
```

3. Create this file:

```bash
backend/.env
```

Use the format from `backend/.env.example`.

4. Start the app:

```bash
npm run dev
```

5. Open:

```text
http://localhost:5173
```

The front-end will proxy `/api` calls to the backend on port 4000.

## Render Hosting Setup

Use this as a single Render Web Service.

Build Command:

```bash
npm install && npm run install-all && npm run build
```

Start Command:

```bash
npm start
```

Environment Variables:

```env
STRIPE_SECRET_KEY=your_private_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_private_webhook_secret
JWT_SECRET=make_a_long_random_secret
FRONTEND_URL=https://your-render-url.onrender.com
NODE_ENV=production
```

After Render gives you a live URL, your Stripe webhook URL will be:

```text
https://your-render-url.onrender.com/api/stripe/webhook
```

Later, after testing, you can connect:

```text
app.primedefensetraining.com
```

and update `FRONTEND_URL` plus Stripe webhook URL accordingly.

## Events Needed in Stripe Webhook

- customer.subscription.created
- customer.subscription.updated
- customer.subscription.deleted
- invoice.payment_succeeded
- invoice.payment_failed

## Current Limitation

This starter uses in-memory storage for member accounts and legal data. That is fine for testing, but production should use a real database like Supabase, PostgreSQL, Firebase, or MongoDB.
