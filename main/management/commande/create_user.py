"""
Script to create default users for testing the application.
Run this script with Django's shell:
    python manage.py shell < create_user.py
"""

import os
import django
import random
from django.core.files.base import ContentFile
from django.contrib.auth import get_user_model
from django.db import transaction
from pathlib import Path

# Initialize Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend_api.settings')  # Replace 'yourproject' with your actual project name
django.setup()

# Import models
from django.contrib.auth import get_user_model
from main.models import Entrepreneur, Investor, Organization  # Replace 'app' with your actual app name

User = get_user_model()

def create_default_users():
    """Create default users for testing the application"""
    
    print("Creating default users for testing...")
    
    users = [
        # Admin user (superuser)
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'admin123',
            'first_name': 'Admin',
            'last_name': 'User',
            'phone': '1234567890',
            'role': 'admin',
            'is_staff': True,
            'is_superuser': True
        },
        
        # Entrepreneur users
        {
            'username': 'entrepreneur1',
            'email': 'entrepreneur1@example.com',
            'password': 'password123',
            'first_name': 'John',
            'last_name': 'Doe',
            'phone': '1112223333',
            'role': 'entrepreneur',
            'profile': {
                'bio': 'Experienced entrepreneur with a passion for technology.'
            }
        },
        {
            'username': 'entrepreneur2',
            'email': 'entrepreneur2@example.com',
            'password': 'password123',
            'first_name': 'Jane',
            'last_name': 'Smith',
            'phone': '2223334444',
            'role': 'entrepreneur',
            'profile': {
                'bio': 'Agriculture entrepreneur focused on sustainable farming.'
            }
        },
        
        # Investor users
        {
            'username': 'investor1',
            'email': 'investor1@example.com',
            'password': 'password123',
            'first_name': 'Robert',
            'last_name': 'Johnson',
            'phone': '3334445555',
            'role': 'investor',
            'profile': {
                'bio': 'Angel investor with focus on tech startups.'
            }
        },
        {
            'username': 'investor2',
            'email': 'investor2@example.com',
            'password': 'password123',
            'first_name': 'Sarah',
            'last_name': 'Williams',
            'phone': '4445556666',
            'role': 'investor',
            'profile': {
                'bio': 'Impact investor looking for sustainable projects.'
            }
        },
        
        # Organization users (NGO/Association)
        {
            'username': 'ngo1',
            'email': 'ngo1@example.com',
            'password': 'password123',
            'phone': '5556667777',
            'role': 'ONG-Association',
            'profile': {
                'organization_name': 'Tech for All',
                'registration_number': 'NGO12345',
                'founded_year': 2015,
                'mission_statement': 'Bridging the digital divide in rural communities.',
                'website_url': 'https://techforall.example.com',
                'bio': 'NGO focused on technology education and access.'
            }
        },
        {
            'username': 'ngo2',
            'email': 'ngo2@example.com',
            'password': 'password123',
            'phone': '6667778888',
            'role': 'ONG-Association',
            'profile': {
                'organization_name': 'Green Future',
                'registration_number': 'NGO67890',
                'founded_year': 2010,
                'mission_statement': 'Creating sustainable agricultural practices.',
                'website_url': 'https://greenfuture.example.com',
                'bio': 'Environmental NGO focused on sustainable farming.'
            }
        }
    ]

    with transaction.atomic():
        for user_data in users:
            # Extract profile data if it exists
            profile_data = user_data.pop('profile', None)
            
            # Check if user already exists
            if not User.objects.filter(username=user_data['username']).exists():
                # Create the user
                user = User.objects.create_user(
                    username=user_data['username'],
                    email=user_data['email'],
                    password=user_data['password'],
                    phone=user_data['phone'],
                    role=user_data['role'],
                    is_staff=user_data.get('is_staff', False),
                    is_superuser=user_data.get('is_superuser', False)
                )
                
                # Set first_name and last_name if provided
                if 'first_name' in user_data:
                    user.first_name = user_data['first_name']
                if 'last_name' in user_data:
                    user.last_name = user_data['last_name']
                
                user.save()
                print(f"Created user: {user.username} ({user.role})")
                
                # Create the appropriate profile based on role
                if user.role == 'entrepreneur' and profile_data:
                    Entrepreneur.objects.create(
                        user=user,
                        first_name=user_data.get('first_name', ''),
                        last_name=user_data.get('last_name', ''),
                        bio=profile_data.get('bio', '')
                    )
                    print(f"Created entrepreneur profile for {user.username}")
                
                elif user.role == 'investor' and profile_data:
                    Investor.objects.create(
                        user=user,
                        first_name=user_data.get('first_name', ''),
                        last_name=user_data.get('last_name', ''),
                        bio=profile_data.get('bio', '')
                    )
                    print(f"Created investor profile for {user.username}")
                
                elif user.role == 'ONG-Association' and profile_data:
                    Organization.objects.create(
                        user=user,
                        organization_name=profile_data.get('organization_name', ''),
                        registration_number=profile_data.get('registration_number', ''),
                        founded_year=profile_data.get('founded_year', 2020),
                        mission_statement=profile_data.get('mission_statement', ''),
                        website_url=profile_data.get('website_url', ''),
                        bio=profile_data.get('bio', '')
                    )
                    print(f"Created organization profile for {user.username}")
            else:
                print(f"User {user_data['username']} already exists.")

if __name__ == "__main__":
    create_default_users()
    print("\nDone! Default users have been created.")