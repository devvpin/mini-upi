# Running Mini-UPI in GitHub Codespaces

Running Mini-UPI in GitHub Codespaces guarantees a clean, isolated Linux container with Docker, PostgreSQL, Python 3.12, and Node.js—completely bypassing Windows Docker or environment pitfalls.

---

## 1. Quick Launch (1 Click)

1. Push your latest code to your GitHub repository.
2. In your browser on GitHub, click the green **`<> Code`** button.
3. Select the **`Codespaces`** tab and click **`Create codespace on main`** (or your active branch).
4. Wait 1–2 minutes for the cloud workspace to initialize.

---

## 2. Start the Stack (One Command)

In the terminal inside Codespaces, run:

```bash
bash scripts/codespaces_setup.sh
```

This automated script will:
- Generate strong cryptographic secrets in `.env` if not present.
- Create `./secrets` directory.
- Spin up all 4 Docker containers (`db`, `api`, `web`, `caddy`).
- Run Alembic database migrations.
- Seed the database with campus departments, classes, students, faculty, and the admin account.

*(Alternatively, you can manually run `make up && make migrate && make seed`)*

---

## 3. Opening the Web App

1. In the bottom panel of Codespaces/VS Code, navigate to the **`PORTS`** tab.
2. Find **Port 80** (labeled `Mini-UPI Application (Web & API)`).
3. Click the **Globe icon** ("Open in Browser") or click the Forwarded Address link.
4. **HTTPS is enabled automatically** by GitHub Codespaces edge proxy, ensuring browser WebCrypto (`crypto.subtle`) non-extractable device key generation operates properly without SSL certificate warnings.

> **Tip for Live Demo / Showing on Phone:**  
> In the **PORTS** tab, right-click **Port 80** -> **Port Visibility** -> change from **Private** to **Public**. You can now scan QR codes or open the exact link on any phone or external browser.

---

## 4. Demo Login Credentials

| Role | Email / Identifier | Password | Notes |
|---|---|---|---|
| **Admin** | `admin01@gcet.edu` | `AdminPassword@123` | Top-up virtual balance, view audit log, manage users |
| **Faculty** | `fac_cp_01@gcet.edu` | `FacultyPassword@123` | ₹2,000 virtual balance |
| **Student** | `22cp010@gcet.edu` | `StudentPassword@123` | ₹1,000 virtual balance |

*On first login for a device, the browser WebCrypto key will be registered and you can set an MPIN (e.g. `123456`).*

---

## 5. Submission & Viva Commands

Run these directly inside the Codespaces terminal during your demo:

```bash
# 1. Run all crypto attack test demonstrations (replay attacks, tampering, 3-strike lockout, etc.)
make attacks-docker

# 2. View live service logs
make logs

# 3. View health and readiness
curl http://localhost/health
curl http://localhost/ready
```
