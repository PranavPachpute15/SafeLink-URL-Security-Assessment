# 🚀 Render Deployment Guide for SafeLink

## Prerequisites
- GitHub account with SafeLink repository
- Render account (sign up at https://render.com)

---

## Step 1: Set Up MySQL Database on Render

1. **Log in to Render** at https://dashboard.render.com
2. Click **"New +"** → **"PostgreSQL"** (Note: Render's free PostgreSQL is easier to set up than MySQL)
3. Fill in details:
   - Name: `safelink-db`
   - Database: `safelink_db`
   - User: `safelink`
   - Copy the **Internal Database URL** (you'll need this later)
4. Click **"Create Database"**

**Alternatively for MySQL:**
- Use a free MySQL provider like **Clever Cloud** or **PlanetScale**
- Or use **Railway's MySQL** plugin and link it to Render

---

## Step 2: Deploy the Streamlit App

1. In Render dashboard, click **"New +"** → **"Web Service"**
2. Connect your GitHub repository:
   - Select your GitHub account
   - Choose `SafeLink-URL-Security-Assessment` repository
3. Configure the service:
   - Name: `safelink`
   - Environment: `Python`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python -m streamlit run app.py --server.port=$PORT --server.address=0.0.0.0`
4. Click **"Advanced"** → Add Environment Variables:

```
DB_HOST=your_database_host
DB_USER=your_database_user
DB_PASSWORD=your_database_password
DB_NAME=safelink_db
DB_PORT=3306
```

5. Click **"Create Web Service"**

---

## Step 3: Wait for Deployment

- Build will take 3-5 minutes
- Once complete, you'll see a URL like: `https://safelink.onrender.com`
- Visit the URL to access your deployed SafeLink app!

---

## Troubleshooting

### Database Connection Issues
- Make sure your database is running
- Verify environment variables are correct
- Check that your database allows external connections

### Build Failures
- Ensure `requirements.txt` is in the root directory
- Check that all dependencies are compatible with Python 3.11

### Application Errors
- Check logs in Render dashboard
- Common issue: Missing ML model files (they're included in the repo)

---

## Important Notes

1. **Free Tier Limitations**: Render's free tier puts services to sleep after 15 minutes of inactivity. First request after sleep takes ~30 seconds to wake up.

2. **Database**: For production, consider using a managed MySQL service. The current code supports both MySQL and can be adapted for PostgreSQL.

3. **Environment Variables**: Never commit `.env` files with real credentials to GitHub!

---

## Quick Reference

| Setting | Value |
|---------|-------|
| Build Command | `pip install -r requirements.txt` |
| Start Command | `python -m streamlit run app.py --server.port=$PORT --server.address=0.0.0.0` |
| Runtime | Python 3.11 |

---

**Need Help?**
- Render Docs: https://render.com/docs
- Streamlit Deployment: https://docs.streamlit.io/streamlit-community-cloud/deploy-your-app
