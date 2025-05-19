# SSO Backend (Laravel)

A Laravel-based Single Sign-On (SSO) backend application that provides authentication, authorization, and user management services.

## Features

- JWT Authentication
- Role-Based Access Control (RBAC)
- User Management
- Application Management
- PDF Generation with DomPDF
- Excel Import/Export functionality
- DataTables integration
- QR Code Generation
- User Impersonation
- Snowflake ID Generation
- Redis Cache Support
- Sweet Alert Integration

## Prerequisites

- PHP >= 8.2
- Composer
- PostgreSQL
- Redis (optional, for caching)

## Technology Stack

- Laravel 11.x
- JWT Auth for API authentication
- Laravel DataTables
- Laravel Excel
- DomPDF
- Simple QR Code
- Laravel Impersonate
- Snowflake ID Generator
- SweetAlert
- Predis (Redis Client)

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

3. Create environment file:
```bash
cp .env.example .env
```

4. Generate application key:
```bash
php artisan key:generate
```

5. Generate JWT secret:
```bash
php artisan jwt:secret
```

6. Configure your .env file with database and other settings:
```env
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=your_database
DB_USERNAME=your_username
DB_PASSWORD=your_password

REDIS_CLIENT=predis
REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

JWT_SECRET=your_jwt_secret
JWT_TTL=60
JWT_REFRESH_TTL=20160

LDAP_HOST=ldap://your-ldap-server
LDAP_PORT=389
LDAP_BASE_DN=dc=example,dc=com
LDAP_USERNAME=cn=admin,dc=example,dc=com
LDAP_PASSWORD=your_ldap_password
LDAP_PEOPLE_OU=ou=people
```

7. Enter PostgreSQL, then type the command:
```bash
CREATE DATABASE uper_idp;
```

8. Import database to PostgreSQL:
```
psql -U <username> -d uper_idp -f database/uper_idp.sql

```

## Apache Configuration

Add this to your Apache virtual host configuration:

```apache
<VirtualHost *:80>
    ServerName sso.local
    DocumentRoot "/var/www/sso/public"
    <Directory "/var/www/sso/public">
        Options Indexes FollowSymLinks MultiViews
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

## Development Server

Start the development server:
```bash
php artisan serve
```

Or use the custom dev command that runs multiple services:
```bash
composer run-script dev
```

This will concurrently run:
- Laravel development server
- Queue worker
- Log viewer (Pail)
- Vite development server

## Available Commands

- `php artisan serve` - Start the development server
- `php artisan migrate` - Run database migrations
- `php artisan db:seed` - Seed the database
- `php artisan queue:work` - Start the queue worker
- `php artisan storage:link` - Create symbolic link for storage

## Security

- All passwords are hashed using SSHA for LDAP storage
- JWT tokens expire after 1 hour
- Password reset tokens expire after 1 hour
- Rate limiting enabled for API endpoints

## Testing

Run the test suite:
```bash
php artisan test
```

## Docker Support

The application includes Docker configurations for different PHP versions (8.0-8.4) and database options (MySQL, MariaDB, PostgreSQL). To use Docker:

1. Choose your configuration in the docker directory
2. Use Laravel Sail:
```bash
./vendor/bin/sail up
```

## Directory Structure

```
app/
├── Exports/       # Excel export classes
├── Helpers/       # Helper functions
├── Http/          # Controllers, Middleware, Requests
├── Imports/       # Excel import classes
├── Models/        # Eloquent models
├── Providers/     # Service providers
├── Services/      # Business logic services
├── Traits/        # Reusable traits
└── Utilities/     # Utility classes

database/
├── factories/     # Model factories
├── migrations/    # Database migrations
└── seeders/      # Database seeders
```

## API Documentation

The application provides RESTful APIs for:
- Authentication (login, logout, refresh token)
- User management
- Role management
- Application management
- Password reset functionality

Detailed API documentation should be maintained separately.

## Security

- JWT-based authentication
- Role-based authorization
- User impersonation logging
- Request rate limiting
- CORS protection

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

## Additional Information

- Uses Snowflake IDs for distributed unique identifiers
- Supports PDF generation for reports
- Excel import/export functionality
- QR code generation capabilities
- Includes user impersonation for admin debugging
- Redis caching support for improved performance
- Sweet Alert integration for better UX
- DataTables for efficient data presentation

## Support

For support, please contact the development team or create an issue in the repository.

## License

The Laravel framework is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).