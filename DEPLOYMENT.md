# 🚀 SMTP EVA Distributed Deployment Guide

> Complete setup guide for deploying the distributed email verification system across AWS EC2 and your dedicated SMTP server.

## 📋 System Overview

The SMTP EVA system is split into two components to handle AWS SMTP port restrictions:

1. **AWS EC2 Instance** - Handles levels 1-4 validation (syntax, DNS, MX, pattern matching)
2. **Dedicated SMTP Server** - Handles level 5 validation (actual SMTP verification)

## 🎯 Architecture Diagram

```
                    ┌─────────────────────────────────┐
                    │         User Requests           │
                    │    (Email Verification API)     │
                    └─────────────┬───────────────────┘
                                  │
                                  ▼
        ┌─────────────────────────────────────────────────┐
        │             AWS EC2 Instance                   │
        │                                                │
        │  ┌─────────────┐  ┌─────────────┐             │
        │  │   Level 1   │  │   Level 2   │             │
        │  │   Syntax    │  │International│             │
        │  │ Validation  │  │   Domain    │             │
        │  └─────────────┘  └─────────────┘             │
        │                                                │
        │  ┌─────────────┐  ┌─────────────┐             │
        │  │   Level 3   │  │   Level 4   │             │
        │  │ DNS/MX Check│  │  Pattern     │             │
        │  │             │  │  Matching    │             │
        │  └─────────────┘  └─────────────┘             │
        └─────────────────┬───────────────────────────────┘
                          │ HTTP API + Auth
                          │ (Only valid emails)
                          ▼
        ┌─────────────────────────────────────────────────┐
        │          Dedicated SMTP Server                 │
        │        (Your own machine/VPS)                  │
        │                                                │
        │           ┌─────────────┐                      │
        │           │   Level 5   │                      │
        │           │ SMTP Verify │◄─────────────────────┤
        │           │ Port 25     │     SMTP:25          │
        │           └─────────────┘     Connections      │
        │                                                │
        └─────────────────────────────────────────────────┘
```

## 🛠️ Part 1: Dedicated SMTP Server Setup

### Prerequisites

- A server/VPS with SMTP port 25 access (not AWS EC2)
- Ubuntu 20.04+ or similar Linux distribution
- Root or sudo access
- Static IP address (recommended)

### Step 1: Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2 for process management
sudo npm install -g pm2

# Create application user
sudo useradd -m -s /bin/bash smtpeva
sudo usermod -aG sudo smtpeva

# Switch to application user
sudo su - smtpeva
```

### Step 2: Deploy SMTP Server

```bash
# Clone the repository
git clone https://github.com/your-username/smtp-eva.git
cd smtp-eva/smtp-server

# Install dependencies
npm install --production

# Copy and configure environment
cp env.example .env
nano .env
```

**Configure `.env`**:
```env
# Server Configuration
PORT=3001
NODE_ENV=production

# Authentication - Generate a strong API key
SMTP_API_KEY=your-super-secret-32-char-api-key-here

# CORS - Replace with your AWS EC2 IP
ALLOWED_ORIGINS=http://YOUR_AWS_EC2_IP:3000

# SMTP Configuration
SMTP_TIMEOUT=15000
SMTP_CONNECTION_TIMEOUT=8000
SMTP_MAX_RETRIES=2
MAX_SMTP_BATCH_SIZE=50

# Logging
LOG_LEVEL=info
```

### Step 3: Generate Strong API Key

```bash
# Generate a secure API key
openssl rand -hex 32
# Example output: a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456

# Use this as your SMTP_API_KEY
```

### Step 4: Configure Firewall

```bash
# Install UFW if not present
sudo apt install ufw

# Reset firewall rules
sudo ufw --force reset

# Allow SSH (IMPORTANT: Do this first!)
sudo ufw allow ssh

# Allow your AWS EC2 instance (replace with actual IP)
sudo ufw allow from YOUR_AWS_EC2_IP to any port 3001

# Allow outbound SMTP connections
sudo ufw allow out 25

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

### Step 5: Test SMTP Connectivity

```bash
# Test SMTP port access
telnet gmail-smtp-in.l.google.com 25

# Expected output:
# Trying 74.125.28.26...
# Connected to gmail-smtp-in.l.google.com.
# Escape character is '^]'.
# 220 mx.google.com ESMTP...

# Type 'quit' to exit
```

### Step 6: Start the Service

```bash
# Start with PM2
pm2 start server.js --name smtp-eva-server

# Save PM2 configuration
pm2 save

# Setup auto-start
pm2 startup
# Follow the instructions provided by the command

# Check status
pm2 status
```

### Step 7: Setup Log Rotation

```bash
# Install logrotate
sudo apt install logrotate

# Create logrotate configuration
sudo nano /etc/logrotate.d/smtp-eva-server
```

Add this content:
```
/home/smtpeva/smtp-eva/smtp-server/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 smtpeva smtpeva
    postrotate
        pm2 reload smtp-eva-server
    endscript
}
```

### Step 8: Verify Installation

```bash
# Check server status
curl http://localhost:3001/api/health

# Expected response:
# {"status":"healthy","service":"SMTP EVA Dedicated Server",...}

# Test with API key
curl -H "X-API-Key: your-api-key" \
     http://localhost:3001/api/smtp/status
```

## ☁️ Part 2: AWS EC2 Instance Setup

### Prerequisites

- AWS EC2 instance (t3.medium or larger recommended)
- Ubuntu 20.04+ AMI
- Security group configured for HTTP/HTTPS access
- Elastic IP (recommended)

### Step 1: EC2 Initial Setup

```bash
# Connect to your EC2 instance
ssh -i your-key.pem ubuntu@your-ec2-ip

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install PM2
sudo npm install -g pm2

# Install MongoDB (optional, if using database)
wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
sudo apt update
sudo apt install -y mongodb-org
sudo systemctl start mongod
sudo systemctl enable mongod
```

### Step 2: Deploy Main Application

```bash
# Clone repository
git clone https://github.com/your-username/smtp-eva.git
cd smtp-eva

# Install dependencies
npm install --production

# Copy and configure environment
cp env.example .env
nano .env
```

**Configure `.env`**:
```env
# Server Configuration
PORT=3000
NODE_ENV=production

# Database Configuration (if using)
MONGODB_URI=mongodb://localhost:27017/smtp-eva

# API Configuration
API_RATE_LIMIT_WINDOW_MS=900000
API_RATE_LIMIT_MAX_REQUESTS=100

# Email Configuration (Levels 1-4, Local AWS EC2)
DNS_TIMEOUT=5000

# External SMTP Server Configuration (Level 5, Dedicated Server)
SMTP_SERVER_URL=http://YOUR_DEDICATED_SERVER_IP:3001
SMTP_API_KEY=your-super-secret-32-char-api-key-here
EXTERNAL_SMTP_TIMEOUT=30000
EXTERNAL_SMTP_RETRIES=2

# Security
JWT_SECRET=your-super-secret-jwt-key-here
API_KEY=your-main-api-key-here

# Logging
LOG_LEVEL=info
LOG_FILE=logs/app.log
```

### Step 3: Configure Security Group

In AWS Console:

1. Go to EC2 → Security Groups
2. Select your instance's security group
3. Add inbound rules:
   - **HTTP**: Port 80, Source: 0.0.0.0/0
   - **HTTPS**: Port 443, Source: 0.0.0.0/0
   - **Custom**: Port 3000, Source: 0.0.0.0/0 (for testing)
   - **SSH**: Port 22, Source: Your IP

### Step 4: Test Communication

```bash
# Test connection to SMTP server
curl -H "X-API-Key: your-smtp-api-key" \
     http://YOUR_DEDICATED_SERVER_IP:3001/api/health

# Expected: {"status":"healthy",...}
```

### Step 5: Start the Main Service

```bash
# Start with PM2
pm2 start server.js --name smtp-eva-main

# Save PM2 configuration
pm2 save

# Setup auto-start
pm2 startup
# Follow the instructions

# Check status
pm2 status
```

### Step 6: Setup Nginx (Optional but Recommended)

```bash
# Install Nginx
sudo apt install nginx

# Create configuration
sudo nano /etc/nginx/sites-available/smtp-eva
```

Add this configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/smtp-eva /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

## 🧪 Part 3: Testing the Complete System

### Test Individual Components

**1. Test SMTP Server Health:**
```bash
curl http://YOUR_DEDICATED_SERVER_IP:3001/api/health
```

**2. Test AWS EC2 Health:**
```bash
curl http://YOUR_AWS_EC2_IP:3000/api/health
```

**3. Test End-to-End Email Verification:**
```bash
curl -X POST http://YOUR_AWS_EC2_IP:3000/api/email/verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@gmail.com",
    "checkDNS": true,
    "checkMX": true,
    "checkSMTP": true
  }'
```

### Expected Response Flow

1. **Levels 1-4** processed on AWS EC2:
   - Syntax validation ✅
   - DNS/MX checks ✅
   - Pattern matching ✅

2. **Level 5** forwarded to dedicated server:
   - SMTP verification ✅
   - Results returned to AWS EC2 ✅

## 🔧 Part 4: Monitoring & Maintenance

### Set Up Monitoring

**1. Log Monitoring:**
```bash
# Monitor AWS EC2 logs
pm2 logs smtp-eva-main

# Monitor SMTP server logs
pm2 logs smtp-eva-server
```

**2. Health Check Scripts:**

Create `/home/ubuntu/health-check.sh` on both servers:
```bash
#!/bin/bash
HEALTH_URL="http://localhost:3000/api/health"  # Adjust port per server
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -eq 200 ]; then
    echo "$(date): Health check PASSED"
else
    echo "$(date): Health check FAILED (HTTP $RESPONSE)"
    # Add restart logic if needed
    # pm2 restart smtp-eva-main
fi
```

```bash
# Make executable
chmod +x /home/ubuntu/health-check.sh

# Add to crontab (run every 5 minutes)
crontab -e
# Add: */5 * * * * /home/ubuntu/health-check.sh >> /var/log/health-check.log
```

### Performance Monitoring

**1. System Resources:**
```bash
# Monitor CPU, memory, disk
htop
df -h
iostat 1

# PM2 monitoring
pm2 monit
```

**2. Application Metrics:**
```bash
# Check processing times in logs
tail -f logs/app.log | grep "processingTime"

# Monitor SMTP server response times
curl -w "@curl-format.txt" -H "X-API-Key: your-key" \
     http://YOUR_DEDICATED_SERVER_IP:3001/api/smtp/status
```

Create `curl-format.txt`:
```
     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n
```

## 🔒 Security Best Practices

### 1. Network Security

- **Use VPC** for AWS EC2 instance
- **Firewall rules** restrict access to necessary ports only
- **API key rotation** every 90 days
- **TLS/SSL** for production traffic

### 2. Application Security

- **Rate limiting** enabled on both servers
- **Input validation** for all API endpoints
- **Error handling** doesn't expose sensitive information
- **Logging** all authentication attempts

### 3. Infrastructure Security

- **Keep systems updated** with security patches
- **Monitor logs** for suspicious activity
- **Backup configurations** regularly
- **Use IAM roles** instead of access keys where possible

## 🚨 Troubleshooting Guide

### Common Issues

**1. SMTP Server Connection Failed:**
```bash
# Check if SMTP server is running
pm2 status

# Check firewall
sudo ufw status

# Test network connectivity
telnet YOUR_DEDICATED_SERVER_IP 3001
```

**2. Authentication Errors:**
```bash
# Verify API keys match
echo $SMTP_API_KEY  # On SMTP server
# Should match SMTP_API_KEY in AWS EC2 .env

# Check header format
curl -v -H "X-API-Key: your-key" ...
```

**3. DNS Resolution Issues:**
```bash
# Test DNS on AWS EC2
nslookup gmail.com
dig gmail.com MX

# Check if DNS timeout is appropriate
# Increase DNS_TIMEOUT in .env if needed
```

**4. High Memory Usage:**
```bash
# Check memory usage
free -m
ps aux --sort=-%mem | head

# Restart services if needed
pm2 restart all
```

### Emergency Recovery

**1. Restart Services:**
```bash
# AWS EC2
pm2 restart smtp-eva-main

# SMTP Server
pm2 restart smtp-eva-server
```

**2. Fallback Configuration:**
If SMTP server is unavailable, the system will continue to work with levels 1-4 validation only. SMTP checks will be marked as failed with appropriate error messages.

**3. Service Recovery:**
```bash
# Full restart with logs
pm2 delete all
pm2 start server.js --name smtp-eva-main
pm2 logs
```

## 📈 Scaling Considerations

### Horizontal Scaling

1. **Multiple SMTP Servers**: Deploy multiple dedicated SMTP servers and use load balancing
2. **AWS Auto Scaling**: Use auto-scaling groups for the EC2 instances
3. **Database Clustering**: Use MongoDB Atlas or cluster setup for high availability

### Vertical Scaling

1. **Increase Instance Size**: Upgrade EC2 instance type as needed
2. **Memory Optimization**: Tune Node.js memory settings
3. **Connection Pooling**: Implement connection pooling for better performance

---

## 🎉 Deployment Complete!

Your distributed SMTP EVA system is now ready to handle email verification at scale while bypassing AWS SMTP port restrictions.

### Quick Reference URLs

- **AWS EC2 API**: `http://your-ec2-ip:3000/api/email/verify`
- **SMTP Server Health**: `http://your-smtp-server-ip:3001/api/health`
- **Main Documentation**: `http://your-ec2-ip:3000/api/email/docs`

**Need help?** Check the troubleshooting guide above or open an issue on GitHub.

---

<div align="center">

**🚀 Distributed email verification system deployed successfully!**

[📖 Main Documentation](README.md) • [🔧 SMTP Server Docs](smtp-server/README.md) • [🐛 Issues](https://github.com/your-username/smtp-eva/issues)

</div> 