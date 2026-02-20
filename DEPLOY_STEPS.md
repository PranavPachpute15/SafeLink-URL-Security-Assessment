# 📱 Render Deployment - Step by Step

## What You Need to Do

### Step 1: Create Render Account
1. Go to **https://render.com**
2. Click **"Sign Up"**
3. Sign up with your **GitHub** account (easiest)
4. Verify your email if needed

---

### Step 2: Create Database (Stores User Data)
1. After logging in, click **"New +"** (blue button, top right)
2. Click **"PostgreSQL"**
3. Fill in:
   - **Name**: `safelink-db`
   - **Database**: `safelink`
   - **User**: `safelink`
4. Click **"Create Database"** (bottom of page)
5. **Wait 1 minute** for it to create
6. On the database page, find **"Internal Database URL"** 
7. Click the **copy button** next to it

---

### Step 3: Create Web Service (Runs Your App)
1. Click **"New +"** again (top right)
2. Click **"Web Service"**
3. Click **"Configure account"** if asked to connect GitHub
4. Find and select **`SafeLink-URL-Security-Assessment`** from your repositories
5. Fill in:
   - **Name**: `safelink`
   - **Environment**: `Python`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python -m streamlit run app.py --server.port=$PORT --server.address=0.0.0.0`
6. Click **"Advanced"**
7. Click **"Add Environment Variable"** and add:
   
   | Key | Value |
   |-----|-------|
   | `DB_HOST` | (paste the host from the database URL you copied) |
   | `DB_USER` | `safelink` |
   | `DB_PASSWORD` | (paste the password from the database URL) |
   | `DB_NAME` | `safelink` |
   | `DB_PORT` | `5432` |

   **Database URL format looks like:** `postgres://user:password@host:5432/database`
   - Extract host (after @, before :)
   - Extract password (between : and @)
   
8. Click **"Create Web Service"**

---

### Step 4: Wait for Deployment
1. Wait **3-5 minutes** for it to build
2. You'll see logs scrolling
3. When it says **"Deployed!"**, you're done!

---

### Step 5: Access Your App
1. Look for a **URL** like: `https://safelink.onrender.com`
2. Click it to open your deployed SafeLink app!

---

## Need Help Extracting Database Info?

Your Database URL looks like this:
```
postgres://safelink:abc123xyz@dpg-xxxxx-a.ondigitalocean.app:5432/safelink
```

Extract these:
- **DB_HOST**: `dpg-xxxxx-a.ondigitalocean.app`
- **DB_USER**: `safelink`
- **DB_PASSWORD**: `abc123xyz`
- **DB_NAME**: `safelink`
- **DB_PORT**: `5432`

---

## That's It!

Your SafeLink URL Security Scanner is now live on the internet!
