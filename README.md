# Prime Defense Protection Member App

## Render settings

Build Command:
```bash
cd backend && npm install && cd ../frontend && npm install && npm run build
```

Start Command:
```bash
cd backend && node server.js
```

Environment Variables in Render:
```env
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_webhook_signing_secret
JWT_SECRET=make_a_long_random_secret
FRONTEND_URL=https://app.primedefensetraining.com
PORT=4000
```

Do not upload a `.env` file with live keys to GitHub.

## Notes
- This version serves the front end from the backend.
- Member accounts and permit data are stored in memory for now, so they reset when the server restarts.
- Next production step is a real database.
