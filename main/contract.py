#contract.py

#contract handler
import os

from django.core.files.base import ContentFile
from django.db import transaction
from django.utils import timezone
import pdfkit
import logging
from django.core.exceptions import ValidationError
import time
from tempfile import NamedTemporaryFile

logger = logging.getLogger(__name__)
class ContractHandler:
    @staticmethod
    def get_wkhtmltopdf_config(settings=None):
        """Get wkhtmltopdf configuration based on environment"""
        wkhtmltopdf_path = getattr(settings, 'WKHTMLTOPDF_PATH', None)

        if wkhtmltopdf_path and os.path.exists(wkhtmltopdf_path):
            return pdfkit.configuration(wkhtmltopdf=wkhtmltopdf_path)

        # Try to find wkhtmltopdf in common locations
        common_paths = [
            'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe',  # Windows
        ]

        for path in common_paths:
            if os.path.exists(path):
                return pdfkit.configuration(wkhtmltopdf=path)

        return None

    @staticmethod
    def generate_pdf_content(html_content):
        """Generate PDF content from HTML with improved Windows compatibility"""
        temp_file = None
        try:
            config = ContractHandler.get_wkhtmltopdf_config()

            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None
            }

            # Generate a unique temporary file name
            timestamp = int(time.time() * 1000)
            temp_path = os.path.join(os.environ.get('TEMP', '/tmp'), f'contract_{timestamp}.pdf')

            if config:
                pdfkit.from_string(
                    html_content,
                    temp_path,
                    options=options,
                    configuration=config
                )
            else:
                raise RuntimeError("PDF generation tool (wkhtmltopdf) not found")

            # Read the generated PDF
            max_retries = 3
            retry_delay = 1  # seconds

            for attempt in range(max_retries):
                try:
                    with open(temp_path, 'rb') as pdf_file:
                        pdf_content = pdf_file.read()
                    break
                except PermissionError:
                    if attempt < max_retries - 1:
                        logger.warning(f"Attempt {attempt + 1}: File busy, retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                    else:
                        raise

            return pdf_content

        except Exception as e:
            logger.error(f"Failed to generate PDF: {str(e)}")
            raise ValidationError(f"PDF generation failed: {str(e)}")

        finally:
            # Clean up: try to delete the temporary file
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except PermissionError:
                    logger.warning(
                        f"Could not delete temporary file {temp_path}. It will be cleaned up by the system later.")
                except Exception as e:
                    logger.warning(f"Error while deleting temporary file: {str(e)}")


    @staticmethod
    def generate_html_content(proposal, contract_type):
        """Generate HTML content based on proposal type with detailed data validation"""
        try:
            logger.info(f"Starting HTML generation for proposal ID: {proposal.id if proposal else 'None'}")

            # Validate proposal object and its attributes
            if not hasattr(proposal, 'help_request'):
                logger.error("Proposal missing help_request attribute")
                raise ValidationError("Invalid proposal: missing help_request")

            if not hasattr(proposal.help_request, 'entrepreneur'):
                logger.error("Help request missing entrepreneur attribute")
                raise ValidationError("Invalid help request: missing entrepreneur")

            if not hasattr(proposal, 'investor'):
                logger.error("Proposal missing investor attribute")
                raise ValidationError("Invalid proposal: missing investor")

            if not hasattr(proposal.help_request, 'project'):
                logger.error("Help request missing project attribute")
                raise ValidationError("Invalid help request: missing project")

            # Log all the data we're about to use
            logger.info(f"""
                    Proposal Data:
                    - Type: {contract_type}
                    - Help Request ID: {proposal.help_request.id}
                    - Entrepreneur ID: {proposal.help_request.entrepreneur.id}
                    - Investor ID: {proposal.investor.id}
                    - Project ID: {proposal.help_request.project.id}
                """)

            # Get entrepreneur details with validation
            entrepreneur = proposal.help_request.entrepreneur
            if not (hasattr(entrepreneur, 'first_name') and hasattr(entrepreneur, 'last_name')):
                logger.error("Entrepreneur missing name attributes")
                raise ValidationError("Invalid entrepreneur data: missing name")
            if not hasattr(entrepreneur, 'user') or not hasattr(entrepreneur.user, 'email'):
                logger.error("Entrepreneur missing user/email attributes")
                raise ValidationError("Invalid entrepreneur data: missing email")

            # Get investor details with validation
            investor = proposal.investor
            if not (hasattr(investor, 'first_name') and hasattr(investor, 'last_name')):
                logger.error("Investor missing name attributes")
                raise ValidationError("Invalid investor data: missing name")
            if not hasattr(investor, 'user') or not hasattr(investor.user, 'email'):
                logger.error("Investor missing user/email attributes")
                raise ValidationError("Invalid investor data: missing email")

            # Get project details with validation
            project = proposal.help_request.project
            if not hasattr(project, 'project_name'):
                logger.error("Project missing name attribute")
                raise ValidationError("Invalid project data: missing name")

            # Build contract data based on type
            if contract_type == 'financial':
                # Validate financial-specific attributes
                if not hasattr(proposal, 'investment_amount'):
                    logger.error("Financial proposal missing investment_amount")
                    raise ValidationError("Invalid financial proposal: missing investment amount")
                if not hasattr(proposal, 'investment_type'):
                    logger.error("Financial proposal missing investment_type")
                    raise ValidationError("Invalid financial proposal: missing investment type")
                if not hasattr(proposal, 'timeline'):
                    logger.error("Financial proposal missing timeline")
                    raise ValidationError("Invalid financial proposal: missing timeline")

                # Get the financial request details
                financial_request = proposal.help_request.financialrequest

                # Calculate financial details
                monthly_payment = financial_request.calculate_monthly_payment()
                total_repayment = financial_request.calculate_total_repayment()
                total_interest = financial_request.calculate_total_interest()

                contract_data = {
                    'contract_type': 'Financial Investment Agreement',
                    'date': timezone.now().strftime("%B %d, %Y"),
                    'entrepreneur_name': f"{entrepreneur.first_name} {entrepreneur.last_name}",
                    'entrepreneur_email': entrepreneur.user.email,
                    'investor_name': f"{investor.first_name} {investor.last_name}",
                    'investor_email': investor.user.email,
                    'project_name': project.project_name,
                    'investment_amount': f"{proposal.investment_amount:,.2f}",
                    'investment_type': proposal.investment_type,
                    'interest_rate': f"{financial_request.interest_rate:.2f}",
                    'duration_months': financial_request.duration_months,
                    'monthly_payment': f"{monthly_payment:,.2f}",
                    'total_repayment': f"{total_repayment:,.2f}",
                    'total_interest': f"{total_interest:,.2f}",
                    'timeline': proposal.timeline,
                    'terms': getattr(proposal, 'terms', 'Standard terms and conditions apply.')
                }
                logger.info("Financial contract data prepared successfully")

            else:  # technical
                # Validate technical-specific attributes
                if not hasattr(proposal, 'expertise'):
                    logger.error("Technical proposal missing expertise")
                    raise ValidationError("Invalid technical proposal: missing expertise")
                if not hasattr(proposal, 'support_duration'):
                    logger.error("Technical proposal missing support_duration")
                    raise ValidationError("Invalid technical proposal: missing support duration")
                if not hasattr(proposal, 'support_type'):
                    logger.error("Technical proposal missing support_type")
                    raise ValidationError("Invalid technical proposal: missing support type")

                contract_data = {
                    'contract_type': 'Technical Support Agreement',
                    'date': timezone.now().strftime("%B %d, %Y"),
                    'entrepreneur_name': f"{entrepreneur.first_name} {entrepreneur.last_name}",
                    'entrepreneur_email': entrepreneur.user.email,
                    'investor_name': f"{investor.first_name} {investor.last_name}",
                    'investor_email': investor.user.email,
                    'project_name': project.project_name,
                    'expertise': proposal.expertise,
                    'support_duration': proposal.support_duration,
                    'support_type': proposal.support_type,
                    'terms': getattr(proposal, 'terms', 'Standard terms and conditions apply.')
                }
                logger.info("Technical contract data prepared successfully")

            # Log the contract data for debugging
            logger.debug(f"Contract data prepared: {contract_data}")

            # Generate HTML template
            html_template = f"""
                            <!DOCTYPE html>
                            <html>
                            <head>
                                <meta charset="UTF-8">
                                <style>
                                    :root {{
                                        --primary-color: #1a5f7a;
                                        --secondary-color: #e8f4f8;
                                        --text-color: #2c3e50;
                                        --border-color: #cbd5e1;
                                        --shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
                                    }}
                            
                                    body {{
                                        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                                        margin: 0;
                                        padding: 40px;
                                        color: var(--text-color);
                                        line-height: 1.8;
                                        background-color: #f9fafb;
                                    }}
                            
                                    .container {{
                                        max-width: 1000px;
                                        margin: 0 auto;
                                        background-color: white;
                                        border-radius: 12px;
                                        box-shadow: var(--shadow);
                                        padding: 40px;
                                    }}
                            
                                    .header {{
                                        text-align: center;
                                        margin-bottom: 50px;
                                        padding: 30px;
                                        background: var(--secondary-color);
                                        border-radius: 12px;
                                        position: relative;
                                    }}
                            
                                    .header:after {{
                                        content: '';
                                        position: absolute;
                                        bottom: 0;
                                        left: 50%;
                                        transform: translateX(-50%);
                                        width: 100px;
                                        height: 4px;
                                        background: var(--primary-color);
                                    }}
                            
                                    .header h1 {{
                                        color: var(--primary-color);
                                        margin: 0 0 15px 0;
                                        font-size: 32px;
                                        font-weight: 700;
                                        letter-spacing: -0.5px;
                                    }}
                            
                                    .header p {{
                                        font-size: 1.1em;
                                        color: var(--text-color);
                                        margin: 0;
                                    }}
                            
                                    .section {{
                                        margin: 40px 0;
                                        padding: 30px;
                                        background: white;
                                        border-radius: 12px;
                                        border: 1px solid var(--border-color);
                                    }}
                            
                                    .section h2 {{
                                        color: var(--primary-color);
                                        font-size: 24px;
                                        margin: 0 0 25px 0;
                                        padding-bottom: 15px;
                                        border-bottom: 2px solid var(--secondary-color);
                                        position: relative;
                                    }}
                            
                                    .section h2:after {{
                                        content: '';
                                        position: absolute;
                                        bottom: -2px;
                                        left: 0;
                                        width: 60px;
                                        height: 2px;
                                        background: var(--primary-color);
                                    }}
                            
                                    .financial-details {{
                                        display: grid;
                                        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                                        gap: 25px;
                                        margin: 20px 0;
                                    }}
                            
                                    .financial-item {{
                                        padding: 20px;
                                        background: var(--secondary-color);
                                        border-radius: 8px;
                                        border: 1px solid var(--border-color);
                                        transition: transform 0.2s ease;
                                    }}
                            
                                    .financial-item:hover {{
                                        transform: translateY(-2px);
                                    }}
                            
                                    .financial-item strong {{
                                        color: var(--primary-color);
                                        font-size: 1.1em;
                                        display: block;
                                        margin-bottom: 8px;
                                    }}
                            
                                    .amount {{
                                        color: var(--primary-color);
                                        font-weight: 600;
                                        font-size: 1.2em;
                                    }}
                            
                                    .currency {{
                                        color: #64748b;
                                        font-size: 0.9em;
                                    }}
                            
                                    .signatures {{
                                        margin-top: 80px;
                                        display: flex;
                                        justify-content: space-between;
                                        flex-wrap: wrap;
                                        gap: 40px;
                                    }}
                            
                                    .signature-block {{
                                        flex: 1;
                                        min-width: 250px;
                                    }}
                            
                                    .signature-line {{
                                        border-top: 2px solid var(--border-color);
                                        width: 100%;
                                        margin: 20px 0;
                                        position: relative;
                                    }}
                            
                                    .signature-line:before {{
                                        content: '×';
                                        position: absolute;
                                        left: -15px;
                                        top: -15px;
                                        color: var(--primary-color);
                                        font-size: 1.2em;
                                    }}
                            
                                    .signature-info {{
                                        font-size: 0.95em;
                                        color: #64748b;
                                        line-height: 1.6;
                                    }}
                            
                                    .terms {{
                                        background: var(--secondary-color);
                                        padding: 25px;
                                        border-radius: 8px;
                                        margin-top: 40px;
                                        border: 1px solid var(--border-color);
                                    }}
                            
                                    @media (max-width: 768px) {{
                                        body {{
                                            padding: 20px;
                                        }}
                                        
                                        .container {{
                                            padding: 20px;
                                        }}
                            
                                        .signatures {{
                                            flex-direction: column;
                                        }}
                            
                                        .signature-block {{
                                            width: 100%;
                                        }}
                                    }}
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <div class="header">
                                        <h1>{contract_data['contract_type']}</h1>
                                        <p>Date: {contract_data['date']}</p>
                                    </div>
                            
                                    <div class="section">
                                        <h2>Parties</h2>
                                        <div class="financial-details">
                                            <div class="financial-item">
                                                <strong>Entrepreneur</strong>
                                                <p>{contract_data['entrepreneur_name']}</p>
                                                <span class="signature-info">Email: {contract_data['entrepreneur_email']}</span>
                                            </div>
                                            <div class="financial-item">
                                                <strong>Investor</strong>
                                                <p>{contract_data['investor_name']}</p>
                                                <span class="signature-info">Email: {contract_data['investor_email']}</span>
                                            </div>
                                        </div>
                                    </div>
                            
                                    <div class="section">
                                        <h2>Project Details</h2>
                                        <div class="financial-item">
                                            <strong>Project Name</strong>
                                            <p>{contract_data['project_name']}</p>
                                        </div>
                                    </div>
                            
                                    <div class="section">
                                        <h2>Agreement Details</h2>
                                        {'<div class="financial-item"><strong>Investment Amount</strong><p class="amount">' + contract_data['investment_amount'] + '</p><span class="currency"> FCFA</span></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Investment Type</strong><p>' + contract_data['investment_type'] + '</p></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Interest Rate</strong><p>' + contract_data['interest_rate'] + '%</p></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Duration (Months)</strong><p>' + str(contract_data['duration_months']) + '</p></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Monthly Payment</strong><p class="amount">' + contract_data['monthly_payment'] + '</p><span class="currency"> FCFA</span></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Total Interest</strong><p class="amount">' + contract_data['total_interest'] + '</p><span class="currency"> FCFA</span></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Total Repayment Amount</strong><p class="amount">' + contract_data['total_repayment'] + '</p><span class="currency"> FCFA</span></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Timeline</strong><p>' + contract_data['timeline'] + '</p></div>' if contract_type == 'financial' else ''}
                                        {'<div class="financial-item"><strong>Expertise Area</strong><p>' + contract_data['expertise'] + '</p></div>' if contract_type == 'technical' else ''}
                                        {'<div class="financial-item"><strong>Support Duration</strong><p>' + contract_data['support_duration'] + '</p></div>' if contract_type == 'technical' else ''}
                                        {'<div class="financial-item"><strong>Support Type</strong><p>' + contract_data['support_type'] + '</p></div>' if contract_type == 'technical' else ''}
                                    </div>
                            
                                    <div class="section">
                                        <h2>Terms and Conditions</h2>
                                        <div class="terms">
                                            <p>{contract_data['terms']}</p>
                                        </div>
                                    </div>
                            
                                    <div class="signatures">
                                        <div class="signature-block">
                                            <div class="signature-line"></div>
                                            <strong>Entrepreneur Signature</strong><br>
                                            <span class="signature-info">{contract_data['entrepreneur_name']}</span>
                                        </div>
                                        <div class="signature-block">
                                            <div class="signature-line"></div>
                                            <strong>Investor Signature</strong><br>
                                            <span class="signature-info">{contract_data['investor_name']}</span>
                                        </div>
                                    </div>
                                </div>
                            </body>
                            </html>
                            """

            logger.info(f"HTML content generated successfully for proposal {proposal.id}")
            return html_template

        except Exception as e:
            logger.error(f"Error generating HTML content: {str(e)}", exc_info=True)
            raise ValidationError(f"HTML content generation failed: {str(e)}")

    @staticmethod
    def create_contract_and_collaboration(proposal, contract_type):
        """Create contract and collaboration records with improved PDF handling"""
        from .models import Contract, Collaboration

        try:
            with transaction.atomic():
                logger.info(f"Starting contract creation for proposal {proposal.id}")

                # Generate HTML content
                html_content = ContractHandler.generate_html_content(proposal, contract_type)
                if not html_content:
                    raise ValidationError("HTML content generation failed")

                # Generate PDF content before creating the contract
                pdf_content = ContractHandler.generate_pdf_content(html_content)

                # Create contract instance
                contract = Contract(
                    contract_type=contract_type,
                    html_content=html_content
                )

                # Set the appropriate proposal field
                if contract_type == 'financial':
                    contract.financial_proposal = proposal
                else:
                    contract.technical_proposal = proposal

                # Save contract first to get an ID
                contract.save()

                # Generate filename and save PDF file
                filename = f'contract_{contract.id}_{timezone.now().strftime("%Y%m%d")}.pdf'
                contract.pdf_file.save(filename, ContentFile(pdf_content), save=True)

                # Create collaboration
                collaboration = Collaboration.objects.create(
                    entrepreneur=proposal.help_request.entrepreneur,
                    investor=proposal.investor,
                    project=proposal.help_request.project,
                    contract=contract,
                    collaboration_type=contract_type,
                    is_active=True
                )

                logger.info(f"Contract {contract.id} and Collaboration {collaboration.id} created successfully")
                return contract, collaboration

        except Exception as e:
            logger.error(f"Contract/collaboration creation failed: {str(e)}", exc_info=True)
            raise ValidationError(f"Failed to create contract and collaboration: {str(e)}")