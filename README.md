# Healthcare Management System (HMS)

A production-ready, HIPAA-compliant Healthcare Management System with embedded AI capabilities.

## Architecture

This system is built with:
- **Backend**: FastAPI (Python) with async support
- **Frontend**: React + Next.js (App Router) with Tailwind CSS
- **Database**: PostgreSQL with FHIR alignment
- **Security**: AES-256 encryption, TLS 1.3, Role-Based Access Control (RBAC)

## Portal Architecture

1. **Public Portal** - Landing page, authentication, provider directory
2. **Patient Portal** - EHR view, appointments, telehealth, prescriptions, billing
3. **Provider Portal** - Dashboard, AI-powered charting, order entry, telehealth
4. **Admin & Billing Portal** - Master scheduling, claims tracking, user provisioning
5. **Super Admin & Analytics** - Compliance logs, MLOps metrics

## Development

### Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

## Current Status

- [x] Project initialization
- [ ] Authentication & Authorization Foundation
- [ ] Database schema & migrations
- [ ] Provider Portal APIs
- [ ] Patient Portal APIs
- [ ] Frontend implementation
