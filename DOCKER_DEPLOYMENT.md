# Docker Production Deployment Guide

## Quick Start

### 1. Prepare Environment
```bash
# Create production environment file
cp .env.production.example .env.production

# Edit with strong values
nano .env.production
```

Generate strong secrets:
```bash
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('DB_PASSWORD=' + secrets.token_urlsafe(32))"
```

### 2. Build and Start Containers
```bash
# Build images
docker-compose build

# Start services (detached)
docker-compose up -d

# Check logs
docker-compose logs -f web
docker-compose logs -f db
```

### 3. Verify Deployment
```bash
# Check services are running
docker-compose ps

# Test the app
curl http://localhost

# Access the app
# Browser: http://your-server-ip
```

### 4. Database Initialization
Database is automatically initialized on first run. To manually initialize:
```bash
docker-compose exec web python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

## Production Checklist

### Security
- [x] HTTPS/SSL configured (uncomment in nginx.conf)
- [x] Strong SECRET_KEY generated
- [x] Strong DATABASE password set
- [x] SESSION_COOKIE_SECURE=True
- [x] FLASK_DEBUG=False
- [x] Security headers configured in Nginx
- [x] Non-root user in Docker
- [ ] Firewall rules configured (only 80, 443 exposed)
- [ ] Regular backups of PostgreSQL database

### Monitoring & Maintenance
```bash
# View logs
docker-compose logs -f

# Backup database
docker-compose exec db pg_dump -U readingnook readingnook > backup.sql

# Restore database
docker-compose exec -T db psql -U readingnook readingnook < backup.sql

# Scale workers (edit docker-compose.yml gunicorn command)
# --workers 8  # for high traffic

# Stop services
docker-compose down

# Remove everything (careful!)
docker-compose down -v
```

## SSL/HTTPS Setup

### Using Let's Encrypt (Recommended)
```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Generate certificate
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
mkdir ssl
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem ssl/key.pem
sudo chown $USER:$USER ssl/*

# Uncomment HTTPS section in nginx.conf
# Update server_name in nginx.conf to your domain

# Restart
docker-compose restart nginx
```

### Auto-renewal
```bash
# Setup cron job for Let's Encrypt renewal
sudo crontab -e

# Add line:
0 0 1 * * certbot renew --quiet && docker-compose restart nginx
```

## Scaling & Performance

### Increase Workers
Edit docker-compose.yml, change gunicorn command:
```bash
gunicorn --bind 0.0.0.0:8000 --workers 8 --timeout 60 ...
```

### Database Optimization
```bash
# Connect to database
docker-compose exec db psql -U readingnook readingnook

# Create indexes for better performance
CREATE INDEX idx_book_user_id ON book(user_id);
CREATE INDEX idx_book_date_read ON book(date_read);
```

## Troubleshooting

### App won't start
```bash
docker-compose logs web
```

### Database connection error
```bash
# Check database is healthy
docker-compose ps
# Should show db as "Up"

# Test connection
docker-compose exec db psql -U readingnook -c "SELECT 1"
```

### High memory usage
```bash
# Reduce workers in docker-compose.yml
--workers 2

# Or limit memory in docker-compose.yml:
# mem_limit: 512m
```

### Need to run migrations
```bash
docker-compose exec web python migrate.py
```

## Backups

### Database Backup
```bash
# Full backup
docker-compose exec db pg_dump -U readingnook readingnook > backup-$(date +%Y%m%d).sql

# Automated daily backup
# Add to crontab:
0 2 * * * docker-compose -f /path/to/docker-compose.yml exec -T db pg_dump -U readingnook readingnook > /backups/readingnook-$(date +\%Y\%m\%d).sql
```

### Volume Backup
```bash
# Backup PostgreSQL volume
docker run --rm -v readingnook_postgres_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/postgres-backup.tar.gz /data
```

## Production URLs

- **App**: http://your-domain.com
- **Admin/Database**: Only accessible internally

## Security Notes

1. **Never commit .env.production to git** - it's in .gitignore
2. **Rotate SECRET_KEY** if compromised
3. **Keep Docker images updated** - `docker-compose pull`
4. **Monitor logs** for suspicious activity
5. **Use strong passwords** for database
6. **Enable HTTPS** in production (not optional!)
7. **Set up firewall** to limit access

## Additional Resources

- Flask Documentation: https://flask.palletsprojects.com/
- Docker Docs: https://docs.docker.com/
- PostgreSQL Docs: https://www.postgresql.org/docs/
- Nginx Docs: https://nginx.org/en/docs/
- Let's Encrypt: https://letsencrypt.org/
