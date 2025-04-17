# Single Sign-On (SSO) System

A secure Single Sign-On system built with Laravel 11 and integrated with LDAP authentication.

## System Requirements

- PHP 8.2 or higher
- Composer 2.0+
- PostgreSQL 13+
- Apache 2.4+
- OpenLDAP 2.5.8

## Features

- LDAP Authentication
- JWT Token-based API
- Password Reset System
- User Management
- Role-based Access Control
- Session Management

## Installation

1. Clone the repository:
```bash
git clone https://github.com/burhanbur/sso-ldap.git
cd sso
```

2. Install PHP dependencies:
```bash
composer install
```

3. Copy environment file:
```bash
copy .env.example .env
```

4. Generate application key:
```bash
php artisan key:generate
```

5. Generate JWT secret:
```bash
php artisan jwt:secret
```

6. Configure your environment variables in `.env`:
```ini
DB_CONNECTION=pgsql
DB_HOST=127.0.0.1
DB_PORT=5432
DB_DATABASE=your_database
DB_USERNAME=your_username
DB_PASSWORD=your_password

LDAP_HOST=ldap://your-ldap-server
LDAP_PORT=389
LDAP_BASE_DN=dc=example,dc=com
LDAP_USERNAME=cn=admin,dc=example,dc=com
LDAP_PASSWORD=your_ldap_password
LDAP_PEOPLE_OU=ou=people
```

7. Run database migrations:
```bash
php artisan migrate
```

## Apache Configuration

Add this to your Apache virtual host configuration:

```apache
<VirtualHost *:80>
    ServerName sso.local
    DocumentRoot "c:/xampp82/htdocs/sso/public"
    <Directory "c:/xampp82/htdocs/sso/public">
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

## API Documentation

### Authentication Endpoints

```
POST /api/login
POST /api/logout
POST /api/refresh
POST /api/forgot-password
POST /api/reset-password
```

### User Management Endpoints

```
GET    /api/users
POST   /api/users
GET    /api/users/{uuid}
PUT    /api/users/{uuid}
DELETE /api/users/{uuid}
```

## Security

- All passwords are hashed using SSHA for LDAP storage
- JWT tokens expire after 1 hour
- Password reset tokens expire after 1 hour
- CSRF protection enabled for web routes
- Rate limiting enabled for API endpoints

## Testing

Run the test suite:

```bash
php artisan test
```

## Troubleshooting

Common issues and solutions:

1. LDAP Connection Failed
   - Check LDAP server is running
   - Verify LDAP credentials in .env
   - Ensure LDAP port is open

2. Database Connection Failed
   - Verify PostgreSQL is running
   - Check database credentials
   - Ensure database exists

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please contact the development team or create an issue in the repository.