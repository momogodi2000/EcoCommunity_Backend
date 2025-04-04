# Community Entrepreneurship Platform Backend

## Project Overview

The Community Entrepreneurship Platform is a digital solution designed to address socio-economic challenges in Cameroon by connecting local entrepreneurs with critical resources, funding, and support networks. This platform aims to reduce unemployment rates, particularly among youth and women, by creating an ecosystem where entrepreneurial initiatives can thrive through increased visibility, funding access, and strategic partnerships.

The platform serves as a bridge between entrepreneurs with innovative ideas and potential backers including investors, NGOs, and public institutions. It facilitates every step of the entrepreneurial journey - from project conceptualization and documentation to securing technical or financial assistance, and finally tracking impact and outcomes.

## Key Stakeholders

- **Entrepreneurs**: Individuals seeking to launch or grow community-based business initiatives
- **Investors**: Entities providing financial backing to promising projects
- **Organizations (NGOs/Associations)**: Groups offering technical expertise, training, and other support
- **Administrators**: Platform managers ensuring quality control and proper operation

## Backend Architecture

This Django REST API serves as the backbone of the platform, providing robust services for user authentication, project management, funding facilitation, networking, and administrative oversight.

### Technical Stack

- **Framework**: Django / Django REST Framework
- **Database**: PostgreSQL
- **Authentication**: JWT (JSON Web Tokens)
- **Documentation**: Swagger / OpenAPI
- **Frontend**: React with Tailwind CSS (separate repository)

## Core Features & API Structure

### User Management

The system supports multiple user types with specific roles and capabilities:

```python
# User model excerpt
class User(AbstractUser):
    phone = models.CharField(max_length=15)
    role = models.CharField(
        max_length=20,
        choices=[
            ('entrepreneur', 'Entrepreneur'),
            ('investor', 'Investisseur'),
            ('ONG-Association', 'ONG-Association'),
            ('admin', 'Admin'),
        ]
    )
```

#### Authentication Endpoints
- `POST /api/register/` - Create a new user account
- `POST /api/login/` - User login
- `POST /api/logout/` - User logout
- `GET /api/user/profile/` - Get user profile
- `PUT /api/user/profile/` - Update user profile

#### Password Management
- `POST /api/password/reset/request/` - Request password reset
- `POST /api/password/reset/verify/` - Verify reset code
- `POST /api/password/reset/confirm/` - Reset password

### Project Management

Projects are the central entity in the system, representing entrepreneurial initiatives:

```python
# Project model excerpt
class Project(models.Model):
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('approved', 'Approuvé'),
        ('rejected', 'Refusé')
    ]
    
    SECTOR_CHOICES = [
        ('agriculture', 'Agriculture'),
        ('technology', 'Technologie'),
        # Additional sectors...
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    entrepreneur = models.ForeignKey(Entrepreneur, on_delete=models.CASCADE)
    project_name = models.CharField(max_length=255)
    sector = models.CharField(max_length=50, choices=SECTOR_CHOICES)
    # Additional fields...
```

#### Project Endpoints
- `GET /api/projects/` - List all projects
- `POST /api/projects/` - Create a new project
- `GET /api/projects/{id}/` - Get project details
- `PUT /api/projects/{id}/` - Update project
- `DELETE /api/projects/{id}/` - Delete project
- `POST /api/projects/{id}/upload-document/` - Upload project documentation
- `POST /api/projects/{id}/update-status/` - Update project status

### Help Request & Proposal System

The platform implements a comprehensive system for requesting and offering assistance:

#### Help Requests
Entrepreneurs can request financial or technical assistance for their projects:
- `POST /api/help-requests/` - Create help request
- `GET /api/help-requests/{id}/` - Get help request details
- `PUT /api/help-requests/{id}/update-status/` - Update help request status

#### Financial & Technical Proposals
Investors can respond to help requests with concrete proposals:
- `GET/POST /api/proposals/{proposal_type}/` - List/create proposals
- `GET/PUT /api/proposals/{proposal_type}/{id}/` - Get/update specific proposal

#### Entrepreneur Proposal Management
- `GET /api/entrepreneur/proposals/` - List all proposals for entrepreneur's projects
- `GET /api/entrepreneur/proposals/{proposal_type}/` - Filter proposals by type
- `GET/PUT /api/entrepreneur/proposals/{proposal_type}/{id}/` - Get/update specific proposal

### Contract & Collaboration Management

Once proposals are accepted, the system facilitates formal agreements:

```python
# Contract model excerpt
class Contract(models.Model):
    CONTRACT_TYPES = [
        ('financial', 'Financial'),
        ('technical', 'Technical')
    ]
    financial_proposal = models.OneToOneField('FinancialProposal', ...)
    technical_proposal = models.OneToOneField('TechnicalProposal', ...)
    contract_type = models.CharField(max_length=20, choices=CONTRACT_TYPES)
    pdf_file = models.FileField(upload_to='contracts/')
    html_content = models.TextField()
    # Additional fields...
```

#### Contract Endpoints
- `GET/POST /api/contracts/` - List/create contracts
- `GET /api/contracts/{proposal_type}/{proposal_id}/` - Get contract details
- `GET /api/contracts/{contract_id}/{action}/` - View/download contract

#### Collaboration Tracking
- `GET/POST /api/collaborations/` - List/create collaborations
- Tracks ongoing relationships between entrepreneurs and investors

### Announcements & Events

Organizations can publish opportunities and organize community events:

```python
# Announcement model excerpt
class Announcement(models.Model):
    ANNOUNCEMENT_TYPES = [
        ('funding', 'Financement'),
        ('training', 'Formation'),
        ('partnership', 'Partenariat'),
        # Additional types...
    ]
    organization = models.ForeignKey('Organization', ...)
    title = models.CharField(max_length=200)
    type = models.CharField(max_length=20, choices=ANNOUNCEMENT_TYPES)
    # Additional fields...
```

#### Announcement Endpoints
- `GET/POST /api/announcements/` - List/create announcements
- `GET/PUT/DELETE /api/announcements/{id}/` - Manage specific announcement
- `GET /api/public/announcements/` - Public access to published announcements

#### Event Management
- `GET/POST /api/events/` - List/create events
- `GET/PUT/DELETE /api/events/{id}/` - Manage specific event
- `GET /api/public/events/` - Public access to published events

### Administration Features

The platform provides tools for administration and oversight:

#### User Administration
- `POST /api/admin/signup` - Admin user creation
- `GET/PUT /api/admin/users` - List/manage all users
- `GET/PUT /api/admin/users/{user_id}` - Manage specific user
- `GET /api/admin/users/stats` - User statistics

#### Analytics
- `GET /api/admin/analytics/` - Platform metrics and insights

## Database Model Structure

### Core User Models
- **User**: Base authentication model with role-based permissions
- **Entrepreneur**: Extended profile for entrepreneurs
- **Investor**: Extended profile for investors
- **Organization**: Extended profile for NGOs and associations

### Project-Related Models
- **Project**: Core entrepreneurial initiative information
- **ProjectDocument**: Attachments and verifications for projects (ID cards, business registers, etc.)

### Help & Support Models
- **HelpRequest**: Base model for assistance requests
- **FinancialRequest**: Extension of HelpRequest for funding needs
- **TechnicalRequest**: Extension of HelpRequest for expertise needs
- **FinancialProposal**: Investor offers for financial assistance
- **TechnicalProposal**: Investor offers for technical assistance

### Formalization Models
- **Contract**: Legal agreement between entrepreneurs and investors
- **Collaboration**: Ongoing relationship tracking

### Community Engagement Models
- **Announcement**: Opportunities shared by organizations
- **Event**: Community gatherings and workshops

## Setup and Installation

### Prerequisites
- Python 3.8+
- PostgreSQL
- Pipenv (recommended)

### Installation Steps
1. Clone the repository
```bash
git clone [repository-url]
cd [project-directory]/backend
```

2. Set up virtual environment
```bash
pipenv install
pipenv shell
```

3. Configure environment variables
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Run migrations
```bash
python manage.py migrate
```

5. Create superuser
```bash
python manage.py createsuperuser
```

6. Run development server
```bash
python manage.py runserver
```

## API Security

### Authentication
- JWT-based authentication for secure API access
- Role-based permissions system
- Token refresh mechanisms

### Data Protection
The API implements security measures in accordance with GDPR requirements:
- User consent management for data collection
- Data encryption in transit and at rest
- Clear terms of use and privacy policy
- Access controls and authentication
- User data management functions (view, edit, delete)

## Development Guidelines

### Code Structure
- Models are organized by functional domain
- Views follow RESTful API design principles
- URLs are named consistently for API navigation

### Testing Strategy
```bash
# Run test suite
python manage.py test
```

Focus areas for testing:
- User authentication flows
- Project creation and approval process
- Financial and technical proposal validation
- Contract generation and signature verification

## Deployment

### Production Requirements
- HTTPS configuration
- Database backup system
- Media file storage (AWS S3 recommended)
- Proper server hardening

### Deployment Options
- Docker containers with Docker Compose
- Cloud platforms (AWS, Azure, GCP)
- VPS with Nginx and Gunicorn

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes using descriptive messages
4. Push to the branch
5. Create a pull request with detailed description

## License

[Specify License]

## Project Context

This platform addresses critical needs in Cameroon's entrepreneurial ecosystem by:
- Reducing unemployment through new business creation
- Enabling rural and underserved communities to access funding
- Creating transparent channels for investment in local businesses
- Building a supportive community of entrepreneurs, investors, and experts

The project aligns with Cameroon's economic development goals and focuses on sustainable, community-driven growth.