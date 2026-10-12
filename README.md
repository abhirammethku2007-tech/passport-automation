# Passport Automation Demo

This is a local educational prototype, not an official passport service. Its files are organized into `frontend/` (website pages, styles, and browser JavaScript), `backend/` (the Node.js server), and `database/` (the SQLite database). Accounts and applications remain available after signing out or restarting the server.

## Run the demo

1. Install Node.js 24 or newer.
2. Open a terminal in this project folder.
3. Run `node backend/server.js`.
4. Open <http://localhost:8000/>.

The first start creates `database/passport-demo.sqlite` automatically. Stop the server with **Ctrl+C**. Keep the database file to preserve demo accounts and applications; copy it while the server is stopped to make a backup.

If you previously used the browser-storage version of this demo on the same browser and website address, its saved applicant accounts and applications are imported into SQLite on your next visit. The old browser copies are cleared after a successful import.

## Separate demo sign-ins

| Page or action | Purpose |
| --- | --- |
| **Register** | Create a new applicant account once. Registration does not submit a passport application or sign in an officer. |
| **Applicant login** | Sign in to an existing applicant account and open the applicant dashboard. |
| **Apply** | Submit a new passport demo application after signing in as an applicant. |
| **My applications** | Review and track the applicant's saved applications from the applicant dashboard. |
| **Officer login** | Sign in to the separate officer account and open the officer review dashboard. An officer cannot sign in through the applicant page. |

To use a different officer password in PowerShell, set `ADMIN_PASSWORD` before starting the server:

```powershell
$env:ADMIN_PASSWORD = "choose-a-local-demo-password"
node backend/server.js
```

The server binds to `127.0.0.1` by default. It is intended for local demonstrations only: do not expose it to the internet or enter real personal details. Applicant passwords are stored as salted password hashes. Document selection saves only the filename; it does not upload the document. Demo payment does not charge money.

## Deploy on Vercel

The Vercel deployment uses the same frontend and API, with a hosted Turso (libSQL) database so accounts, sessions, and applications persist between serverless requests. The local SQLite file is not uploaded or used by Vercel.

1. Create a Turso database and an authentication token. Keep both private.
2. In Vercel, import `abhirammethku2007-tech/passport-automation` from GitHub. Use the repository root as the project root, **Other** as the framework preset, and Node.js 24. `vercel.json` serves the site from `frontend/`; the `api/` function serves the backend.
3. Add these environment variables in the Vercel project settings for **Production**, **Preview**, and **Development** as needed:
   - `TURSO_DATABASE_URL`: the Turso database URL, such as `libsql://your-database-your-org.turso.io`
   - `TURSO_AUTH_TOKEN`: a token for that database
   - `ADMIN_EMAIL`: officer login email (defaults to `admin@passport.demo`)
   - `ADMIN_PASSWORD`: a unique password of at least 12 characters; production deliberately refuses to start the API without it.
4. Redeploy after adding the variables. The API creates its schema in Turso on first use. Keep the Turso database private, and never add its token, deployment passwords, or the local SQLite database to GitHub.

The GitHub repository is [abhirammethku2007-tech/passport-automation](https://github.com/abhirammethku2007-tech/passport-automation).
