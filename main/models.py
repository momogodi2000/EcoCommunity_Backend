from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from datetime import datetime
from django.core.files.base import ContentFile
import pdfkit
from django.core.exceptions import ValidationError

from django.db.models import Q
import logging

from .contract import ContractHandler

class User(AbstractUser):
    phone = models.CharField(max_length=15)
    role = models.CharField(
        max_length=20,
        choices=[
            ('entrepreneur', 'Entrepreneur'),
            ('investor', 'Investisseur'),
            ('ONG-Association', 'ONG-Association'),
            ('admin', 'Admin'),  # Add this line
        ]
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_blocked = models.BooleanField(default=False)
    profile_image = models.ImageField(upload_to='profile_images/', null=True, blank=True)

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='custom_user_groups',  # Unique name for reverse relation
        blank=True
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='custom_user_permissions',  # Unique name for reverse relation
        blank=True
    )

    class Meta:
        db_table = 'users'


class Entrepreneur(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    bio = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'entrepreneurs'

class Investor(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    bio = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'investors'

class Organization(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization_name = models.CharField(max_length=200)
    registration_number = models.CharField(max_length=100)
    founded_year = models.IntegerField(
        validators=[
            MinValueValidator(1900),
            MaxValueValidator(datetime.now().year)
        ]
    )
    mission_statement = models.TextField(blank=True)
    website_url = models.URLField(blank=True)
    bio = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'organizations'

#Creation of project
class Project(models.Model):
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('approved', 'Approuvé'),
        ('rejected', 'Refusé')
    ]

    SECTOR_CHOICES = [
        ('agriculture', 'Agriculture'),
        ('technology', 'Technologie'),
        ('crafts', 'Artisanat'),
        ('commerce', 'Commerce'),
        ('education', 'Éducation'),
        ('healthcare', 'Santé'),
        ('tourism', 'Tourisme'),
        ('manufacturing', 'Industrie'),
        ('services', 'Services')
    ]

    # Creator Information
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_projects')
    entrepreneur = models.ForeignKey(Entrepreneur, on_delete=models.CASCADE, related_name='entrepreneur_projects')

    # Basic Information
    project_name = models.CharField(max_length=255)
    sector = models.CharField(max_length=50, choices=SECTOR_CHOICES)
    description = models.TextField(blank=True, null=True)

    # Detailed Information
    specific_objectives = models.TextField(blank=True, null=True)
    target_audience = models.CharField(max_length=255)
    estimated_budget = models.DecimalField(max_digits=12, decimal_places=2)
    financing_plan = models.CharField(max_length=255)

    # Status and Timestamps
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    admin_comments = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.project_name} - {self.get_status_display()}"

    def save(self, *args, **kwargs):
        # If this is a new project (no ID yet), set the entrepreneur
        if not self.pk and self.user and not self.entrepreneur:
            try:
                self.entrepreneur = Entrepreneur.objects.get(user=self.user)
            except Entrepreneur.DoesNotExist:
                raise ValueError("Entrepreneur object does not exist for the current user.")
        super().save(*args, **kwargs)


class ProjectDocument(models.Model):
    DOCUMENT_TYPES = [
        ('id_card', 'Carte Nationale d\'Identité'),
        ('business_register', 'Registre de Commerce'),
        ('company_statutes', 'Statuts de l\'Entreprise'),
        ('tax_clearance', 'Attestation de Non Redevance Fiscale'),
        ('permits', 'Permis et Licences'),
        ('intellectual_property', 'Propriété Intellectuelle'),
        ('photos', 'photo'),
        ('feasibility_study', 'Étude de Faisabilité'),
        ('project_photos', 'project_image')  # Add this new type

    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='documents')
    document_type = models.CharField(max_length=50, choices=DOCUMENT_TYPES)
    file = models.FileField(upload_to='project_documents/%Y/%m/%d/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_required = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['project', 'document_type'],
                condition=~Q(document_type='photo'),  # Fixed condition
                name='unique_document_type_per_project'
            )
        ]

    def __str__(self):
        return f"{self.project.project_name} - {self.get_document_type_display()}"


class HelpRequest(models.Model):
    REQUEST_TYPE_CHOICES = [
        ('technical', 'Technical Help'),
        ('financial', 'Financial Help')
    ]

    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed')
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='help_requests')
    entrepreneur = models.ForeignKey(Entrepreneur, on_delete=models.CASCADE)
    request_type = models.CharField(max_length=20, choices=REQUEST_TYPE_CHOICES)
    specific_need = models.CharField(max_length=255)
    description = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class FinancialRequest(models.Model):
    help_request = models.OneToOneField(HelpRequest, on_delete=models.CASCADE)
    amount_requested = models.DecimalField(max_digits=12, decimal_places=2)
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, default=5.00)  # Default 5% interest
    duration_months = models.IntegerField()  # Loan duration in months

    def calculate_monthly_payment(self):
        """Calculate monthly payment using amortization formula"""
        principal = float(self.amount_requested)
        rate = float(self.interest_rate) / 100 / 12  # Monthly interest rate
        n = self.duration_months

        if rate == 0:
            return principal / n

        monthly_payment = principal * (rate * (1 + rate) ** n) / ((1 + rate) ** n - 1)
        return round(monthly_payment, 2)

    def calculate_total_repayment(self):
        """Calculate total repayment amount"""
        monthly_payment = self.calculate_monthly_payment()
        total_repayment = monthly_payment * self.duration_months
        return round(total_repayment, 2)

    def calculate_total_interest(self):
        """Calculate total interest to be paid"""
        return round(self.calculate_total_repayment() - float(self.amount_requested), 2)


class TechnicalRequest(models.Model):
    help_request = models.OneToOneField(HelpRequest, on_delete=models.CASCADE)
    expertise_needed = models.CharField(max_length=255)
    estimated_duration = models.IntegerField(help_text="Estimated duration in days")


class HelpProposal(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('refused', 'Refused')
    ]

    help_request = models.ForeignKey('HelpRequest', on_delete=models.CASCADE)
    investor = models.ForeignKey('Investor', on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class FinancialProposal(HelpProposal):
    help_request = models.ForeignKey(
        'HelpRequest',
        on_delete=models.CASCADE,
        related_name='financial_proposals'
    )
    investor = models.ForeignKey(
        'Investor',
        on_delete=models.CASCADE,
        related_name='financial_proposals'
    )
    investment_amount = models.DecimalField(max_digits=12, decimal_places=2)
    investment_type = models.CharField(max_length=50)  # equity, loan, grant, revenue-sharing
    payment_schedule = models.CharField(max_length=50)  # single, monthly, quarterly, custom
    expected_return = models.TextField()
    timeline = models.TextField()
    additional_terms = models.TextField(blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.status == 'accepted':
            # Calculate total accepted amount for this help request
            accepted_proposals = FinancialProposal.objects.filter(
                help_request=self.help_request,
                status='accepted'
            ).exclude(id=self.id)

            total_accepted = sum(p.investment_amount for p in accepted_proposals)
            total_with_current = total_accepted + self.investment_amount

            # Check if total accepted amount would exceed requested amount
            if total_with_current > self.help_request.financialrequest.amount_requested:
                raise ValidationError("Total accepted investments would exceed requested amount")

        super().save(*args, **kwargs)


class TechnicalProposal(HelpProposal):
    help_request = models.ForeignKey(
        'HelpRequest',
        on_delete=models.CASCADE,
        related_name='technical_proposals'
    )
    investor = models.ForeignKey(
        'Investor',
        on_delete=models.CASCADE,
        related_name='technical_proposals'
    )
    expertise = models.TextField()
    experience_level = models.CharField(max_length=50)  # junior, intermediate, senior, expert
    availability = models.TextField()
    support_duration = models.CharField(max_length=100)
    support_type = models.CharField(max_length=50)  # mentoring, development, review, consulting
    proposed_approach = models.TextField()
    additional_resources = models.TextField(blank=True, null=True)
    expected_outcomes = models.TextField()

logger = logging.getLogger(__name__)
class Contract(models.Model):
    CONTRACT_TYPES = [
        ('financial', 'Financial'),
        ('technical', 'Technical')
    ]

    financial_proposal = models.OneToOneField(
        'FinancialProposal',
        on_delete=models.CASCADE,
        related_name='contract',
        null=True,
        blank=True
    )
    technical_proposal = models.OneToOneField(
        'TechnicalProposal',
        on_delete=models.CASCADE,
        related_name='contract',
        null=True,
        blank=True
    )
    contract_type = models.CharField(max_length=20, choices=CONTRACT_TYPES)
    pdf_file = models.FileField(upload_to='contracts/')
    html_content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    signature_entrepreneur = models.DateTimeField(null=True, blank=True)
    signature_investor = models.DateTimeField(null=True, blank=True)

    def clean(self):
        # Ensure only one type of proposal is set
        if (self.financial_proposal and self.technical_proposal) or \
                (not self.financial_proposal and not self.technical_proposal):
            raise ValidationError('Exactly one proposal type must be set')

        # Ensure contract_type matches proposal type
        if self.financial_proposal and self.contract_type != 'financial':
            raise ValidationError('Contract type must match proposal type')
        if self.technical_proposal and self.contract_type != 'technical':
            raise ValidationError('Contract type must match proposal type')

    def get_proposal(self):
        """Helper method to get the associated proposal regardless of type"""
        return self.financial_proposal or self.technical_proposal

class Collaboration(models.Model):
    entrepreneur = models.ForeignKey(
        'Entrepreneur',
        on_delete=models.CASCADE,
        related_name='collaborations'
    )
    investor = models.ForeignKey(
        'Investor',
        on_delete=models.CASCADE,
        related_name='collaborations'
    )
    project = models.ForeignKey(
        'Project',
        on_delete=models.CASCADE,
        related_name='collaborations'
    )
    contract = models.ForeignKey(
        Contract,
        on_delete=models.SET_NULL,
        null=True,
        related_name='collaboration'
    )
    start_date = models.DateTimeField(auto_now_add=True)
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    collaboration_type = models.CharField(max_length=20, choices=Contract.CONTRACT_TYPES)

    class Meta:
        unique_together = ['entrepreneur', 'investor', 'project', 'contract']


#Anouncement creation
class Announcement(models.Model):
    ANNOUNCEMENT_TYPES = [
        ('funding', 'Financement'),
        ('training', 'Formation'),
        ('partnership', 'Partenariat'),
        ('event', 'Événement'),
        ('opportunity', 'Opportunité'),
    ]

    STATUS_CHOICES = [
        ('draft', 'Brouillon'),
        ('published', 'Publié'),
    ]

    organization = models.ForeignKey('Organization', on_delete=models.CASCADE, related_name='announcements')
    title = models.CharField(max_length=200)
    type = models.CharField(max_length=20, choices=ANNOUNCEMENT_TYPES)
    description = models.TextField()
    location = models.CharField(max_length=100)
    deadline = models.DateField()
    budget = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    requirements = models.JSONField(default=list)
    contact_email = models.EmailField()
    contact_phone = models.CharField(max_length=20, blank=True)
    image = models.ImageField(upload_to='announcements/', null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'announcements'
        ordering = ['-created_at']

#Event creation
class Event(models.Model):
    """
    Model to represent events created by organizations (NGOs/Associations)
    """
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='events'
    )
    title = models.CharField(max_length=200)

    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('published', 'Published')
    ]
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='draft'
    )

    EVENT_TYPES = [
        ('forum', 'forum'),
        ('workshop', 'workshop'),
        ('webinars', 'webinars'),
        ('conference', 'conference')
    ]
    type = models.CharField(max_length=20, choices=EVENT_TYPES)

    description = models.TextField()
    image = models.ImageField(
        upload_to='events/',
        null=True,
        blank=True
    )

    date = models.DateField()
    time = models.TimeField()
    location = models.CharField(max_length=300)

    capacity = models.PositiveIntegerField(
        validators=[MinValueValidator(1)]
    )

    registration_deadline = models.DateField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'events'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} - {self.date}"

    @property
    def is_draft(self):
        return self.status == 'draft'