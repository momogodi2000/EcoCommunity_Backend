import base64
import json
import os
import random
import traceback
import uuid
from collections import defaultdict

import yagmail
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db.models.functions import TruncMonth
from django.http import FileResponse
from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import transaction
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.db.models import Count, Q, Sum, When, Case, F, ExpressionWrapper, FloatField  # Added Q here
from django.shortcuts import get_object_or_404
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password, make_password

from .contract import ContractHandler
from rest_framework.parsers import MultiPartParser, FormParser
from django.db.models.functions import TruncMonth, ExtractMonth
from django.utils import timezone
from datetime import timedelta
import pdfkit
import logging



from django.contrib.auth import get_user_model
from django.conf import settings
from .models import Organization, Entrepreneur, Investor, ProjectDocument, Project, HelpRequest, TechnicalRequest, \
    FinancialRequest, FinancialProposal, TechnicalProposal, Collaboration, Contract, User, Announcement, Event
from .permission import IsProposalOwnerOrRequestEntrepreneur
from .serializers import OrganizationSerializer, EntrepreneurSerializer, UserUpdateSerializer, UserListSerializer, \
    UserCreateSerializer, InvestorSerializer, ProjectSerializer, FinancialRequestSerializer, TechnicalRequestSerializer, \
    HelpRequestSerializer, TechnicalProposalSerializer, FinancialProposalSerializer, CollaborationSerializer, \
    ContractSerializer, CollaborationStatsSerializer, AnnouncementSerializer, EventSerializer, \
    OrganizationDetailSerializer, UserDetailSerializer, OrganizationUpdateSerializer, PasswordUpdateSerializer, \
    EntrepreneurProfileSerializer, InvestorProfileSerializer, OrganizationProfileSerializer, \
    PasswordResetConfirmSerializer, VerifyResetCodeSerializer, PasswordResetRequestSerializer

CustomUser = get_user_model()


class RegisterView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access this view

    @transaction.atomic
    def post(self, request):
        role = request.data.get('role')

        if role == 'ONG-Association':
            serializer = OrganizationSerializer(data=request.data)
        elif role == 'investor':
            serializer = InvestorSerializer(data=request.data)  # Create a separate serializer if needed
        else:
            serializer = EntrepreneurSerializer(data=request.data)

        if serializer.is_valid():
            # Create User instance
            user_data = {
                'email': serializer.validated_data['user']['email'],
                'phone': serializer.validated_data['user']['phone'],
                'username': serializer.validated_data['user']['email'],  # Using email as username
                'password': make_password(serializer.validated_data['password']),
                'role': role
            }
            user = User.objects.create(**user_data)

            # Create profile based on role
            if role == 'ONG-Association':
                Organization.objects.create(
                    user=user,
                    organization_name=serializer.validated_data['organization_name'],
                    registration_number=serializer.validated_data['registration_number'],
                    founded_year=serializer.validated_data['founded_year'],
                    mission_statement=serializer.validated_data.get('mission_statement', ''),
                    website_url=serializer.validated_data.get('website_url', '')
                )
            elif role == 'entrepreneur':
                Entrepreneur.objects.create(
                    user=user,
                    first_name=serializer.validated_data['first_name'],
                    last_name=serializer.validated_data['last_name']
                )
            elif role == 'investor':
                Investor.objects.create(
                    user=user,
                    first_name=serializer.validated_data['first_name'],
                    last_name=serializer.validated_data['last_name']
                )
            else:
                raise ValueError(f"Unknown role: {role}")

            return Response({
                'message': 'Registration successful',
                'user_id': user.id
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    authentication_classes = []  # Disable authentication for this endpoint
    permission_classes = [AllowAny]  # Allow access to anyone

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        user = authenticate(username=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)

            return Response({
                'tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                },
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'role': user.role,
                }
            })
        else:
            return Response(
                {'error': 'Invalid credentials'},
                status=status.HTTP_401_UNAUTHORIZED
            )

class LogoutView(APIView):
        permission_classes = (IsAuthenticated,)

        def post(self, request):
            try:
                # Get the refresh token from the request data
                refresh_token = request.data.get('refresh_token')

                if refresh_token:
                    # Get token object from refresh token
                    token = RefreshToken(refresh_token)
                    # Blacklist the token
                    token.blacklist()

                    return Response(
                        {"message": "Logout successful"},
                        status=status.HTTP_205_RESET_CONTENT
                    )
                else:
                    return Response(
                        {"error": "Refresh token is required"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            except Exception as e:
                return Response(
                    {"error": "Invalid token"},
                    status=status.HTTP_400_BAD_REQUEST
                )

#Forgot Password
# Email configuration
username = "yvangodimomo@gmail.com"
password = "pzls apph esje cgdl"
yag = yagmail.SMTP(username, password)

def generate_reset_code():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = PasswordResetRequestSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data['email']

                try:
                    user = CustomUser.objects.get(email=email)
                except CustomUser.DoesNotExist:
                    return Response(
                        {'error': 'No account found with this email'},
                        status=status.HTTP_404_NOT_FOUND
                    )

                reset_code = generate_reset_code()
                cache_key = f'password_reset_{email}'
                cache.set(cache_key, reset_code, timeout=300)

                subject = "Password Reset Code"
                contents = [
                    f"Your password reset code is: {reset_code}",
                    "This code will expire in 5 minutes.",
                    "If you didn't request this reset, please ignore this email."
                ]

                yag.send(to=email, subject=subject, contents=contents)

                return Response({
                    'message': 'Reset code sent successfully',
                    'email': email
                })
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyResetCodeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = VerifyResetCodeSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data['email']
                submitted_code = serializer.validated_data['code']

                cache_key = f'password_reset_{email}'
                stored_code = cache.get(cache_key)

                if not stored_code:
                    return Response(
                        {'error': 'Reset code has expired'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                if submitted_code != stored_code:
                    return Response(
                        {'error': 'Invalid reset code'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                return Response({'message': 'Code verified successfully'})
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = PasswordResetConfirmSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data['email']
                submitted_code = serializer.validated_data['code']
                new_password = serializer.validated_data['new_password']

                cache_key = f'password_reset_{email}'
                stored_code = cache.get(cache_key)

                if not stored_code or submitted_code != stored_code:
                    return Response(
                        {'error': 'Invalid or expired reset code'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                try:
                    user = CustomUser.objects.get(email=email)
                    validate_password(new_password, user)
                    user.set_password(new_password)
                    user.save()

                    cache.delete(cache_key)

                    subject = "Password Reset Successful"
                    contents = [
                        "Your password has been successfully reset.",
                        "If you didn't make this change, please contact support immediately."
                    ]
                    yag.send(to=email, subject=subject, contents=contents)

                    return Response({'message': 'Password reset successful'})
                except CustomUser.DoesNotExist:
                    return Response(
                        {'error': 'User not found'},
                        status=status.HTTP_404_NOT_FOUND
                    )
                except ValidationError as e:
                    return Response(
                        {'error': e.messages},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#admin signup
class AdminSignupView(APIView):
    #permission_classes = [IsAdminUser]  # Only existing admins can create new admins
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')

        if not all([email, password, first_name, last_name]):
            return Response({
                'error': 'All fields are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({
                'error': 'Email already exists'
            }, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create(
            email=email,
            username=email,
            password=make_password(password),
            first_name=first_name,
            last_name=last_name,
            is_staff=True,
            is_superuser=True,
            role='admin'
        )

        return Response({
            'message': 'Admin created successfully',
            'user_id': user.id
        }, status=status.HTTP_201_CREATED)

#Users settings
class UserView(APIView):
    permission_classes = [IsAuthenticated]

    def _get_user(self, request, user_id=None):
        """Helper method to get user and check permissions"""
        if user_id is None:
            return request.user

        if not request.user.is_staff and str(request.user.id) != str(user_id):
            raise PermissionError('Permission denied')

        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise User.DoesNotExist('User not found')

    def _get_serializer_class(self, user):
        """Helper method to get appropriate serializer based on user role"""
        if user.role == 'entrepreneur':
            return EntrepreneurProfileSerializer
        elif user.role == 'investor':
            return InvestorProfileSerializer
        elif user.role == 'ONG-Association':
            return OrganizationProfileSerializer
        raise ValueError(f"Invalid user role: {user.role}")

    def _get_profile_instance(self, user):
        """Helper method to get profile instance based on user role"""
        if user.role == 'entrepreneur':
            return user.entrepreneur
        elif user.role == 'investor':
            return user.investor
        elif user.role == 'ONG-Association':
            return user.organization
        raise ValueError(f"Invalid user role: {user.role}")

    def get(self, request, user_id=None):
        """Get user profile"""
        try:
            user = self._get_user(request, user_id)
            profile = self._get_profile_instance(user)
            serializer_class = self._get_serializer_class(user)
            serializer = serializer_class(profile)
            return Response(serializer.data)
        except (PermissionError, User.DoesNotExist) as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN if isinstance(e, PermissionError)
                else status.HTTP_404_NOT_FOUND
            )
        except (Entrepreneur.DoesNotExist, Investor.DoesNotExist, Organization.DoesNotExist):
            return Response(
                {'error': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    @transaction.atomic
    def patch(self, request, user_id=None):
        """Update user profile or password"""
        try:
            user = self._get_user(request, user_id)
        except (PermissionError, User.DoesNotExist) as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN if isinstance(e, PermissionError)
                else status.HTTP_404_NOT_FOUND
            )

        # Handle password update
        if 'new_password' in request.data:
            return self._update_password(request, user)

        try:
            profile = self._get_profile_instance(user)
            serializer_class = self._get_serializer_class(user)
            serializer = serializer_class(profile, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data)
        except (Entrepreneur.DoesNotExist, Investor.DoesNotExist, Organization.DoesNotExist):
            return Response(
                {'error': 'Profile not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    def _update_password(self, request, user):
        """Helper method to handle password updates"""
        serializer = PasswordUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Only check current password for non-admin users changing their own password
        if not request.user.is_staff or user.id == request.user.id:
            if not check_password(serializer.validated_data['current_password'], user.password):
                return Response(
                    {'error': 'Current password is incorrect'},
                    status=status.HTTP_400_BAD_REQUEST
                )

        user.password = make_password(serializer.validated_data['new_password'])
        user.save()
        return Response({'message': 'Password updated successfully'})

    def post(self, request, user_id=None):
        """Update user profile image"""
        try:
            user = self._get_user(request, user_id)
        except (PermissionError, User.DoesNotExist) as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN if isinstance(e, PermissionError)
                else status.HTTP_404_NOT_FOUND
            )

        if 'profile_image' not in request.FILES:
            return Response(
                {'error': 'No image file provided'},
                status=status.HTTP_400_BAD_REQUEST
            )

        image = request.FILES['profile_image']

        # Delete old image if it exists
        if user.profile_image:
            default_storage.delete(user.profile_image.path)

        # Save new image
        filename = f'profile_images/user_{user.id}_{image.name}'
        user.profile_image = default_storage.save(filename, image)
        user.save()

        return Response({
            'message': 'Profile image updated successfully',
            'image_url': user.profile_image.url
        })

    @transaction.atomic
    def delete(self, request, user_id=None):
        """Delete user account"""
        try:
            user = self._get_user(request, user_id)
            user.delete()
            return Response({'message': 'Account deleted successfully'})
        except (PermissionError, User.DoesNotExist) as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_403_FORBIDDEN if isinstance(e, PermissionError)
                else status.HTTP_404_NOT_FOUND
            )

# Admin handling users
class UserManagementView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request, user_id=None):
        """Get list of users with filtering and search"""
        if user_id:
            user = get_object_or_404(User, id=user_id)
            if user.role == 'ONG-Association':
                serializer = OrganizationDetailSerializer(user.organization)
            else:
                serializer = UserDetailSerializer(user)
            return Response(serializer.data)


        users = User.objects.all()

        # Handle role filtering
        role = request.query_params.get('role')
        if role:
            users = users.filter(role=role)

        # Handle search
        search = request.query_params.get('search')
        if search:
            users = users.filter(
                Q(email__icontains=search) |
                Q(entrepreneur__first_name__icontains=search) |
                Q(entrepreneur__last_name__icontains=search) |
                Q(organization__organization_name__icontains=search)
            )

        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data)

    @transaction.atomic
    def post(self, request):
        """Create a new user"""
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            try:
                user = serializer.save()
                return Response(UserListSerializer(user).data, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response(
                    {'error': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(
            {'error': serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )

    def delete(self, request, user_id):
        """Delete a user"""
        user = get_object_or_404(User, id=user_id)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @transaction.atomic
    def patch(self, request, user_id):
        """Update user details"""
        user = get_object_or_404(User, id=user_id)
        print("Received data:", request.data)  # Debug line

        # Handle status update
        if 'is_blocked' in request.data:
            user.is_blocked = request.data['is_blocked']
            user.is_active = not user.is_blocked
            user.save()
            return Response(UserListSerializer(user).data)

        # Handle user details update
        try:
            with transaction.atomic():
                # First update the user model
                if 'email' in request.data:
                    user.email = request.data['email']
                if 'phone' in request.data:
                    user.phone = request.data['phone']
                if 'password' in request.data and request.data['password']:
                    user.set_password(request.data['password'])

                user.save()
                print("User saved:", user.email, user.phone)  # Debug line

                # Then update the profile based on role
                if user.role == 'ONG-Association':
                    org = user.organization
                    org_fields = ['organization_name', 'registration_number',
                                  'founded_year', 'mission_statement', 'website_url']

                    for field in org_fields:
                        if field in request.data:
                            setattr(org, field, request.data[field])
                    org.save()
                    print("Organization saved:", org.organization_name)  # Debug line

                elif user.role in ['entrepreneur', 'investor']:
                    profile = getattr(user, user.role.lower(), None)
                    if profile and ('first_name' in request.data or 'last_name' in request.data):
                        if 'first_name' in request.data:
                            profile.first_name = request.data['first_name']
                        if 'last_name' in request.data:
                            profile.last_name = request.data['last_name']
                        profile.save()
                        print(f"{user.role} profile saved:", profile.first_name, profile.last_name)  # Debug line

                # Fetch fresh data to return
                if user.role == 'ONG-Association':
                    serializer = OrganizationDetailSerializer(user.organization)
                else:
                    serializer = UserDetailSerializer(user)

                # Always include status fields in response
                response_data = serializer.data
                response_data.update({
                    'status': 'Inactif' if user.is_blocked else 'Actif',
                    'is_blocked': user.is_blocked
                })

                return Response(serializer.data)

        except Exception as e:
            print("Error saving user:", str(e))  # Debug line
            return Response(
                {'error': f'Failed to update user: {str(e)}'},
                status=status.HTTP_400_BAD_REQUEST
            )

class UserStatsView(APIView):
    permission_classes = [IsAdminUser]

    def get(self, request):
        """Get user statistics"""
        total_users = User.objects.count()
        pending_validation = User.objects.filter(is_active=False).count()
        blocked_users = User.objects.filter(is_active=False, is_blocked=True).count()

        stats = {
            "total_users": total_users,
            "pending_validation": pending_validation,
            "blocked_users": blocked_users,
            "role_distribution": {
                "entrepreneur": User.objects.filter(role='entrepreneur').count(),
                "investor": User.objects.filter(role='investor').count(),
                "ong_association": User.objects.filter(role='ONG-Association').count()
            }
        }

        return Response(stats)

#Project
class ProjectAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        user = request.user
        if user.is_staff:
            projects = Project.objects.all()
        else:
            try:
                entrepreneur = Entrepreneur.objects.get(user=user)
                projects = Project.objects.filter(entrepreneur=entrepreneur)
            except Entrepreneur.DoesNotExist:
                projects = Project.objects.none()

        serializer = ProjectSerializer(projects, many=True, context={'request': request})
        data = serializer.data

        # Add debugging
        for project in data:
            if project.get('project_image'):
                print(f"Project {project['project_name']} image URL: {project['project_image']}")
            for doc in project.get('documents', []):
                if doc['document_type'] == 'project_photos':
                    print(f"Project {project['project_name']} document URL: {doc['file']}")

        return Response(data)

    def post(self, request):
        try:
            # Get the entrepreneur instance
            entrepreneur = Entrepreneur.objects.get(user=request.user)

            # Create a new project with entrepreneur and user
            serializer = ProjectSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                serializer.save(user=request.user, entrepreneur=entrepreneur)
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Entrepreneur.DoesNotExist:
            return Response(
                {"error": "Entrepreneur profile not found for this user"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
    def put(self, request, pk):
        # Update an existing project
        project = get_object_or_404(Project, pk=pk)
        self.check_object_permissions(request, project)
        serializer = ProjectSerializer(project, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        # Delete a project
        project = get_object_or_404(Project, pk=pk)
        self.check_object_permissions(request, project)
        project.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProjectUploadDocumentAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        project = get_object_or_404(Project, pk=pk)
        self.check_object_permissions(request, project)

        document_type = request.data.get('document_type')
        file = request.data.get('file')

        if not document_type or not file:
            return Response(
                {'error': 'Both document_type and file are required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Validate file type for project images
            if document_type == 'project_image':
                allowed_types = ['image/jpeg', 'image/png', 'image/jpg']
                if file.content_type not in allowed_types:
                    return Response(
                        {'error': 'Only JPEG, JPG and PNG files are allowed for project images'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Remove old project image if it exists
                ProjectDocument.objects.filter(
                    project=project,
                    document_type='project_image'
                ).delete()

            if document_type in ['photo', 'project_image']:
                # Handle photos and project images
                document = ProjectDocument.objects.create(
                    project=project,
                    document_type=document_type,
                    file=file
                )
            else:
                # Update or create other document types
                document, created = ProjectDocument.objects.update_or_create(
                    project=project,
                    document_type=document_type,
                    defaults={'file': file}
                )

            return Response({
                'message': 'Document uploaded successfully',
                'document_id': document.id,
                'file_url': document.file.url if document_type == 'project_image' else None
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class ProjectUpdateStatusAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        if not request.user.is_staff:
            return Response({
                'error': 'Only admin users can update project status'
            }, status=status.HTTP_403_FORBIDDEN)

        project = get_object_or_404(Project, pk=pk)
        new_status = request.data.get('status')
        comments = request.data.get('comments')

        if new_status not in dict(Project.STATUS_CHOICES):
            return Response({
                'error': 'Invalid status'
            }, status=status.HTTP_400_BAD_REQUEST)

        project.status = new_status
        project.admin_comments = comments
        project.save()

        return Response({
            'message': 'Project status updated successfully',
            'status': project.get_status_display()
        })

class HelpRequestAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        """Get a single help request or list of help requests"""
        if pk:
            try:
                help_request = HelpRequest.objects.get(pk=pk)
                serializer = HelpRequestSerializer(help_request, context={'request': request})
                return Response(serializer.data)
            except HelpRequest.DoesNotExist:
                return Response(
                    {"error": "Help request not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

        # Filter requests based on user role
        if request.user.role == 'entrepreneur':
            help_requests = HelpRequest.objects.filter(entrepreneur__user=request.user)
        else:
            help_requests = HelpRequest.objects.all()

        serializer = HelpRequestSerializer(help_requests, many=True, context={'request': request})
        return Response(serializer.data)

    def get_accepted_amount(self, request, pk):
        """Get total accepted amount for a financial help request"""
        try:
            help_request = HelpRequest.objects.get(
                pk=pk,
                entrepreneur=request.user.entrepreneur
            )

            # Get all accepted financial proposals
            accepted_proposals = FinancialProposal.objects.filter(
                help_request=help_request,
                status='accepted'
            )

            # Calculate total accepted amount
            total_accepted = sum(
                proposal.investment_amount
                for proposal in accepted_proposals
            )

            # Get total requested amount
            total_requested = help_request.financialrequest.amount_requested

            return Response({
                'accepted_amount': float(total_accepted),
                'requested_amount': float(total_requested),
                'remaining_amount': float(total_requested - total_accepted)
            })

        except HelpRequest.DoesNotExist:
            return Response(
                {"error": "Help request not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        try:
            entrepreneur = Entrepreneur.objects.get(user=request.user)
        except Entrepreneur.DoesNotExist:
            return Response(
                {"error": "Entrepreneur profile not found"},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = HelpRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        help_request = serializer.save(entrepreneur=entrepreneur)

        # Handle specific request type details
        if help_request.request_type == 'financial':
            financial_data = request.data.get('financial_details', {})
            financial_serializer = FinancialRequestSerializer(data=financial_data)
            financial_serializer.is_valid(raise_exception=True)
            financial_serializer.save(help_request=help_request)

        elif help_request.request_type == 'technical':
            technical_data = request.data.get('technical_details', {})
            technical_serializer = TechnicalRequestSerializer(data=technical_data)
            technical_serializer.is_valid(raise_exception=True)
            technical_serializer.save(help_request=help_request)

        # In HelpRequestAPIView.post()
        return Response(
            HelpRequestSerializer(help_request, context={'request': request}).data,
            status=status.HTTP_201_CREATED
        )

    @transaction.atomic  # Important pour la cohérence des données
    def put(self, request, pk):
        """Update an existing help request"""
        try:
            help_request = HelpRequest.objects.get(pk=pk)

            # Check if user has permission to update
            if help_request.entrepreneur.user != request.user:
                return Response(
                    {"error": "You don't have permission to update this request"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Update main help request data
            serializer = HelpRequestSerializer(help_request, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            updated_request = serializer.save()

            # Update financial details if present
            if updated_request.request_type == 'financial' and 'financial_details' in request.data:
                financial_details = request.data['financial_details']
                try:
                    financial_instance = FinancialRequest.objects.get(help_request=help_request)
                    financial_serializer = FinancialRequestSerializer(
                        financial_instance,
                        data=financial_details,
                        partial=True
                    )
                except FinancialRequest.DoesNotExist:
                    financial_serializer = FinancialRequestSerializer(data=financial_details)

                financial_serializer.is_valid(raise_exception=True)
                financial_serializer.save(help_request=updated_request)

            # Update technical details if present
            if updated_request.request_type == 'technical' and 'technical_details' in request.data:
                technical_details = request.data['technical_details']
                try:
                    technical_instance = TechnicalRequest.objects.get(help_request=help_request)
                    technical_serializer = TechnicalRequestSerializer(
                        technical_instance,
                        data=technical_details,
                        partial=True
                    )
                except TechnicalRequest.DoesNotExist:
                    technical_serializer = TechnicalRequestSerializer(data=technical_details)

                technical_serializer.is_valid(raise_exception=True)
                technical_serializer.save(help_request=updated_request)

            # Return updated help request with all details
            return Response(HelpRequestSerializer(updated_request).data)

        except HelpRequest.DoesNotExist:
            return Response(
                {"error": "Help request not found"},
                status=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, pk):
        """Delete a help request"""
        try:
            help_request = HelpRequest.objects.get(pk=pk)

            # Check if user has permission to delete
            if request.user.role != 'admin' and help_request.entrepreneur.user != request.user:
                return Response(
                    {"error": "You don't have permission to delete this request"},
                    status=status.HTTP_403_FORBIDDEN
                )

            help_request.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)

        except HelpRequest.DoesNotExist:
            return Response(
                {"error": "Help request not found"},
                status=status.HTTP_404_NOT_FOUND
            )


class HelpUpdateStatusAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            help_request = HelpRequest.objects.get(pk=pk)

            # Allow both staff users and the entrepreneur who created the request
            if not (help_request.entrepreneur.user == request.user):
                return Response({
                    'error': 'You do not have permission to update this request'
                }, status=status.HTTP_403_FORBIDDEN)

            new_status = request.data.get('status')

            if new_status not in dict(HelpRequest.STATUS_CHOICES):
                return Response({
                    'error': 'Invalid status'
                }, status=status.HTTP_400_BAD_REQUEST)

            help_request.status = new_status
            help_request.save()

            return Response({
                'message': 'Help request status updated successfully',
                'status': new_status
            })

        except HelpRequest.DoesNotExist:
            return Response({
                'error': 'Help request not found'
            }, status=status.HTTP_404_NOT_FOUND)


class HelpProposalView(APIView):
    permission_classes = [IsAuthenticated, IsProposalOwnerOrRequestEntrepreneur]

    def post(self, request, proposal_type):
        try:
            investor = request.user.investor
        except Investor.DoesNotExist:
            return Response(
                {"error": "Only investors can submit proposals"},
                status=status.HTTP_403_FORBIDDEN
            )

        if proposal_type == 'financial':
            serializer = FinancialProposalSerializer(data=request.data)
        elif proposal_type == 'technical':
            serializer = TechnicalProposalSerializer(data=request.data)
        else:
            return Response(
                {"error": "Invalid proposal type"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if serializer.is_valid():
            serializer.save(investor=investor)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request, proposal_type, pk=None):
        try:
            investor = request.user.investor
        except Investor.DoesNotExist:
            return Response(
                {"error": "Only investors can view proposals"},
                status=status.HTTP_403_FORBIDDEN
            )

        if proposal_type == 'financial':
            proposals = investor.financial_proposals.all()
            serializer_class = FinancialProposalSerializer
        elif proposal_type == 'technical':
            proposals = investor.technical_proposals.all()
            serializer_class = TechnicalProposalSerializer
        else:
            return Response(
                {"error": "Invalid proposal type"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if pk:
            try:
                proposal = proposals.get(pk=pk)
                serializer = serializer_class(proposal)
            except (FinancialProposal.DoesNotExist, TechnicalProposal.DoesNotExist):
                return Response(
                    {"error": "Proposal not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            serializer = serializer_class(proposals, many=True)

        return Response(serializer.data)

    def patch(self, request, proposal_type, pk):
        try:
            investor = request.user.investor
        except Investor.DoesNotExist:
            return Response(
                {"error": "Only investors can update proposals"},
                status=status.HTTP_403_FORBIDDEN
            )

        if proposal_type == 'financial':
            try:
                proposal = FinancialProposal.objects.get(pk=pk, investor=investor)
                serializer_class = FinancialProposalSerializer
            except FinancialProposal.DoesNotExist:
                return Response(
                    {"error": "Proposal not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        elif proposal_type == 'technical':
            try:
                proposal = TechnicalProposal.objects.get(pk=pk, investor=investor)
                serializer_class = TechnicalProposalSerializer
            except TechnicalProposal.DoesNotExist:
                return Response(
                    {"error": "Proposal not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            return Response(
                {"error": "Invalid proposal type"},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = serializer_class(proposal, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, proposal_type, pk):
        try:
            investor = request.user.investor
        except Investor.DoesNotExist:
            return Response(
                {"error": "Only investors can delete proposals"},
                status=status.HTTP_403_FORBIDDEN
            )

        if proposal_type == 'financial':
            try:
                proposal = FinancialProposal.objects.get(pk=pk, investor=investor)
            except FinancialProposal.DoesNotExist:
                return Response(
                    {"error": "Proposal not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        elif proposal_type == 'technical':
            try:
                proposal = TechnicalProposal.objects.get(pk=pk, investor=investor)
            except TechnicalProposal.DoesNotExist:
                return Response(
                    {"error": "Proposal not found"},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            return Response(
                {"error": "Invalid proposal type"},
                status=status.HTTP_400_BAD_REQUEST
            )

        proposal.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

logger = logging.getLogger(__name__)
class EntrepreneurProposalView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, proposal_type=None):
        """Get all proposals for entrepreneur's help requests"""
        try:
            entrepreneur = request.user.entrepreneur
        except Entrepreneur.DoesNotExist:
            return Response(
                {"error": "Only entrepreneurs can view their request proposals"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get all help requests from this entrepreneur
        help_requests = HelpRequest.objects.filter(entrepreneur=entrepreneur)

        if proposal_type == 'financial':
            proposals = FinancialProposal.objects.filter(help_request__in=help_requests)
            serializer = FinancialProposalSerializer(proposals, many=True)
        elif proposal_type == 'technical':
            proposals = TechnicalProposal.objects.filter(help_request__in=help_requests)
            serializer = TechnicalProposalSerializer(proposals, many=True)
        else:
            # If no type specified, get both types
            financial_proposals = FinancialProposal.objects.filter(help_request__in=help_requests)
            technical_proposals = TechnicalProposal.objects.filter(help_request__in=help_requests)

            response_data = {
                'financial_proposals': FinancialProposalSerializer(financial_proposals, many=True).data,
                'technical_proposals': TechnicalProposalSerializer(technical_proposals, many=True).data
            }
            return Response(response_data)

        return Response(serializer.data)

    def patch(self, request, proposal_type, pk):
        """Update proposal status and handle contract/collaboration creation"""
        logger.info(f"Processing PATCH request for {proposal_type} proposal {pk}")

        try:
            # Validate user is entrepreneur
            try:
                entrepreneur = request.user.entrepreneur
            except Entrepreneur.DoesNotExist:
                return Response(
                    {"error": "Only entrepreneurs can update proposal status"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Validate status
            new_status = request.data.get('status')
            if not new_status:
                return Response(
                    {"error": "Status field is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            if new_status not in ['accepted', 'refused']:
                return Response(
                    {"error": "Invalid status. Must be 'accepted' or 'refused'"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get the appropriate proposal model and serializer
            if proposal_type == 'financial':
                ProposalModel = FinancialProposal
                ProposalSerializer = FinancialProposalSerializer
            elif proposal_type == 'technical':
                ProposalModel = TechnicalProposal
                ProposalSerializer = TechnicalProposalSerializer
            else:
                return Response(
                    {"error": "Invalid proposal type"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            with transaction.atomic():
                # Get and validate proposal
                try:
                    proposal = ProposalModel.objects.select_for_update().get(
                        pk=pk,
                        help_request__entrepreneur=entrepreneur
                    )
                except ProposalModel.DoesNotExist:
                    return Response(
                        {"error": "Proposal not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Check if proposal is already processed
                if proposal.status in ['accepted', 'refused']:
                    return Response(
                        {"error": f"Proposal is already {proposal.status}"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                if new_status == 'accepted':
                    if proposal_type == 'financial':
                        # Validate total accepted amount
                        accepted_proposals = FinancialProposal.objects.filter(
                            help_request=proposal.help_request,
                            status='accepted'
                        )
                        total_accepted = sum(p.investment_amount for p in accepted_proposals)
                        total_with_current = total_accepted + proposal.investment_amount

                        if total_with_current > proposal.help_request.financialrequest.amount_requested:
                            return Response(
                                {"error": "Accepting this proposal would exceed the requested amount"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:  # technical
                        # Check if there's already an accepted technical proposal
                        existing_accepted = TechnicalProposal.objects.filter(
                            help_request=proposal.help_request,
                            status='accepted'
                        ).exists()

                        if existing_accepted:
                            return Response(
                                {"error": "Another technical proposal is already accepted"},
                                status=status.HTTP_400_BAD_REQUEST
                            )

                        # Refuse other technical proposals
                        proposal.help_request.technical_proposals.exclude(pk=pk).update(status='refused')

                # Update proposal status
                proposal.status = new_status
                proposal.save()

                # If accepted, create contract and collaboration
                if new_status == 'accepted':
                    try:
                        contract, collaboration = ContractHandler.create_contract_and_collaboration(
                            proposal,
                            proposal_type
                        )
                    except Exception as e:
                        logger.error(f"Error creating contract/collaboration: {str(e)}")
                        raise ValidationError("Failed to create contract and collaboration")

                    return Response({
                        'proposal': ProposalSerializer(proposal).data,
                        'contract_id': contract.id,
                        'collaboration_id': collaboration.id,
                        'message': 'Proposal accepted. Contract and collaboration created.'
                    })

                return Response({
                    'proposal': ProposalSerializer(proposal).data,
                    'message': 'Proposal refused successfully.'
                })

        except ValidationError as e:
            logger.error(f"Validation error: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return Response(
                {"error": "An unexpected error occurred"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#Contract and collaborations
class CollaborationAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if hasattr(user, 'entrepreneur'):
            collaborations = Collaboration.objects.filter(entrepreneur=user.entrepreneur)

            # Calculate statistics
            stats = {
                'total_collaborations': collaborations.count(),
                'financial_collaborations': collaborations.filter(collaboration_type='financial').count(),
                'technical_collaborations': collaborations.filter(collaboration_type='technical').count(),
                'total_investment_amount': collaborations.filter(
                    collaboration_type='financial'
                ).aggregate(
                    total=Sum('contract__financial_proposal__investment_amount')
                )['total'] or 0
            }
        elif hasattr(user, 'investor'):
            collaborations = Collaboration.objects.filter(investor=user.investor)

            # Calculate statistics
            stats = {
                'total_collaborations': collaborations.count(),
                'financial_collaborations': collaborations.filter(collaboration_type='financial').count(),
                'technical_collaborations': collaborations.filter(collaboration_type='technical').count(),
                'total_investment_amount': collaborations.filter(
                    collaboration_type='financial'
                ).aggregate(
                    total=Sum('contract__financial_proposal__investment_amount')
                )['total'] or 0
            }
        else:
            collaborations = Collaboration.objects.none()

        serializer = CollaborationSerializer(collaborations, many=True)
        stats_serializer = CollaborationStatsSerializer(stats)

        response_data = {
            'stats': stats_serializer.data,
            'collaborations': serializer.data
        }

        return Response(response_data, status=status.HTTP_200_OK)

class ContractAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, proposal_type=None, proposal_id=None):
        user = request.user
        if hasattr(user, 'entrepreneur'):
            # Modify this query to correctly filter contracts for the entrepreneur
            contracts = Contract.objects.filter(
                Q(financial_proposal__help_request__entrepreneur=user.entrepreneur) |
                Q(technical_proposal__help_request__entrepreneur=user.entrepreneur)
            )
        elif hasattr(user, 'investor'):
            contracts = Contract.objects.filter(
                Q(financial_proposal__investor=user.investor) |
                Q(technical_proposal__investor=user.investor)
            )
        else:
            contracts = Contract.objects.none()

        if proposal_type and proposal_id:
            contracts = contracts.filter(
                Q(financial_proposal__type=proposal_type, financial_proposal_id=proposal_id) |
                Q(technical_proposal__type=proposal_type, technical_proposal_id=proposal_id)
            )

        serializer = ContractSerializer(contracts, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ContractViewDownloadAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get_contract(self, contract_id):
        try:
            contract = Contract.objects.get(id=contract_id)
            # Check if user has permission to access this contract
            user = self.request.user
            if hasattr(user, 'entrepreneur'):
                # Handle both financial and technical proposals
                if contract.financial_proposal:
                    has_access = contract.financial_proposal.help_request.entrepreneur == user.entrepreneur
                elif contract.technical_proposal:
                    has_access = contract.technical_proposal.help_request.entrepreneur == user.entrepreneur
                else:
                    return None

                if not has_access:
                    return None

            elif hasattr(user, 'investor'):
                # Handle both financial and technical proposals
                if contract.financial_proposal:
                    has_access = contract.financial_proposal.investor == user.investor
                elif contract.technical_proposal:
                    has_access = contract.technical_proposal.investor == user.investor
                else:
                    return None

                if not has_access:
                    return None

            return contract
        except Contract.DoesNotExist:
            return None

    def get(self, request, contract_id, action):
        contract = self.get_contract(contract_id)
        if not contract:
            return Response(
                {"error": "Contract not found or access denied"},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            if not contract.pdf_file:
                return Response(
                    {"error": "PDF file not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Get the file path
            file_path = contract.pdf_file.path

            if not os.path.exists(file_path):
                return Response(
                    {"error": "PDF file not found on server"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Open the file
            pdf_file = open(file_path, 'rb')

            if action == "view":
                response = FileResponse(pdf_file, content_type='application/pdf')
                response['Content-Disposition'] = 'inline'
                # Add headers to prevent caching
                response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response['Pragma'] = 'no-cache'
                response['Expires'] = '0'
                return response

            elif action == "download":
                # Get the appropriate proposal based on contract type
                proposal = contract.financial_proposal or contract.technical_proposal
                if proposal and proposal.help_request:
                    project_name = proposal.help_request.project.project_name
                else:
                    project_name = 'unknown_project'

                filename = f"{project_name}_{contract.contract_type}.pdf"
                response = FileResponse(pdf_file, content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response

            else:
                pdf_file.close()
                return Response(
                    {"error": "Invalid action"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#Organisation announcement
class AnnouncementAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request):
        """
        Create a new announcement with detailed error logging.
        """
        try:
            # Log request data for debugging
            logger.debug(f"Request data: {request.data}")
            logger.debug(f"Request FILES: {request.FILES}")

            if request.user.role != 'ONG-Association':
                return Response(
                    {"detail": "Only organizations can create announcements"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Get the organization
            organization = get_object_or_404(Organization, user=request.user)

            # Create a mutable copy of the data
            mutable_data = request.data.copy()

            # Handle requirements field
            if 'requirements' in mutable_data:
                try:
                    # If it's already a string, try to validate it's proper JSON
                    requirements_str = mutable_data['requirements']
                    if isinstance(requirements_str, str):
                        # Try to parse and re-serialize to ensure valid JSON
                        import json
                        requirements_list = json.loads(requirements_str)
                        if not isinstance(requirements_list, list):
                            requirements_list = [requirements_list]
                        # Store back as a JSON string
                        mutable_data['requirements'] = json.dumps(requirements_list)
                except json.JSONDecodeError as e:
                    logger.error(f"Requirements JSON decode error: {str(e)}")
                    return Response(
                        {"requirements": "Invalid JSON format"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Handle image file
            if 'image' in request.FILES:
                mutable_data['image'] = request.FILES['image']

            # Create serializer with processed data
            serializer = AnnouncementSerializer(data=mutable_data)

            if not serializer.is_valid():
                logger.error(f"Serializer errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            # Save announcement
            try:
                announcement = serializer.save(organization=organization)
                logger.info(f"Announcement created successfully: {announcement.id}")
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            except Exception as e:
                logger.error(f"Error saving announcement: {str(e)}")
                raise

        except Exception as e:
            logger.error(f"Unexpected error in announcement creation: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response(
                {"detail": f"An unexpected error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request):
        """
        Retrieve announcements with type-specific filtering options.
        """
        announcement_type = request.query_params.get('type')
        if request.user.role == 'ONG-Association':
            queryset = Announcement.objects.filter(organization__user=request.user)
        else:
            queryset = Announcement.objects.all()

        # Apply type filter if specified
        if announcement_type:
            queryset = queryset.filter(type=announcement_type)

        serializer = AnnouncementSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, pk):
        """
        Delete announcement and its associated image.
        """
        try:
            announcement = get_object_or_404(Announcement, pk=pk, organization__user=request.user)

            # Delete associated image if it exists
            if announcement.image:
                try:
                    default_storage.delete(announcement.image.path)
                except Exception as e:
                    # Log the error but continue with announcement deletion
                    print(f"Error deleting image: {str(e)}")

            announcement.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def patch(self, request, pk=None):
        """
        Update an announcement with improved error handling and validation.
        """
        try:
            # Get the announcement instance
            announcement = get_object_or_404(Announcement, pk=pk, organization__user=request.user)

            # Create a mutable copy of the data
            mutable_data = request.data.copy()

            # Handle requirements field
            if 'requirements' in mutable_data:
                try:
                    # Handle both string and list inputs for requirements
                    if isinstance(mutable_data['requirements'], str):
                        import json
                        requirements = json.loads(mutable_data['requirements'])
                        if not isinstance(requirements, list):
                            return Response(
                                {"requirements": "Requirements must be a list"},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    elif isinstance(mutable_data['requirements'], list):
                        requirements = mutable_data['requirements']
                    else:
                        return Response(
                            {"requirements": "Invalid requirements format"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    # Validate each requirement
                    if not all(isinstance(req, str) for req in requirements):
                        return Response(
                            {"requirements": "All requirements must be strings"},
                            status=status.HTTP_400_BAD_REQUEST
                        )

                    mutable_data['requirements'] = requirements
                except json.JSONDecodeError:
                    return Response(
                        {"requirements": "Invalid JSON format for requirements"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Handle image field
            if 'image' in request.FILES:
                mutable_data['image'] = request.FILES['image']

            # Create serializer with the announcement instance and processed data
            serializer = AnnouncementSerializer(
                announcement,
                data=mutable_data,
                partial=True  # Allow partial updates
            )

            if not serializer.is_valid():
                logger.error(f"Validation errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            # Save the updated announcement
            updated_announcement = serializer.save()

            # Return the updated data
            return Response(
                AnnouncementSerializer(updated_announcement).data,
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Error updating announcement: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response(
                {"detail": "An error occurred while updating the announcement"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def update_status(self, request, announcement):
        """
        Handle status updates specifically
        """
        try:
            new_status = request.data.get('status')

            # Validate the status
            if new_status not in dict(Announcement.STATUS_CHOICES):
                return Response(
                    {"status": "Invalid status value"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Validate status transition
            if announcement.status == 'published' and new_status == 'draft':
                return Response(
                    {"status": "Cannot change status from published to draft"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update the status
            announcement.status = new_status
            announcement.save(update_fields=['status'])

            return Response(
                AnnouncementSerializer(announcement).data,
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Error updating announcement status: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response(
                {"detail": "An error occurred while updating the status"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

#Organisation event
class EventManagementView(APIView):
    permission_classes = [IsAuthenticated]

    def get_organization(self, request):
        if request.user.role != 'ONG-Association':
            raise PermissionError("Only organizations can manage events")
        return request.user.organization

    def process_image(self, base64_data):
        try:
            if not base64_data:
                return None

            image_data = base64.b64decode(base64_data)
            if len(image_data) > 5 * 1024 * 1024:
                raise ValueError("Image size should not exceed 5MB")

            filename = f"event_image_{uuid.uuid4()}.png"
            return ContentFile(image_data, name=filename)
        except Exception as e:
            raise ValueError(f"Invalid image data: {str(e)}")

    def post(self, request):
        try:
            organization = self.get_organization(request)
            data = request.data.copy()

            # Process image if present
            image_data = data.pop('image', None)
            try:
                if image_data:
                    image_file = self.process_image(image_data)
                    data['image'] = image_file
            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            serializer = EventSerializer(data=data, context={'request': request, 'organization': organization})
            if serializer.is_valid():
                event = serializer.save(organization=organization)
                return Response(EventSerializer(event).data, status=status.HTTP_201_CREATED)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PermissionError as e:
            return Response({"error": str(e)}, status=status.HTTP_403_FORBIDDEN)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get(self, request, event_id=None):
        try:
            organization = self.get_organization(request)
            if event_id:
                event = get_object_or_404(Event, id=event_id, organization=organization)
                return Response(EventSerializer(event).data)

            events = Event.objects.filter(organization=organization)
            return Response(EventSerializer(events, many=True).data)
        except PermissionError as e:
            return Response({"error": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, event_id):
        try:
            organization = self.get_organization(request)
            event = get_object_or_404(Event, id=event_id, organization=organization)
            data = request.data.copy()

            # Process image if present
            image_data = data.pop('image', None)
            try:
                if image_data:
                    image_file = self.process_image(image_data)
                    if event.image:
                        event.image.delete(save=False)
                    data['image'] = image_file
            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            serializer = EventSerializer(event, data=data, context={'request': request})
            if serializer.is_valid():
                updated_event = serializer.save()
                return Response(EventSerializer(updated_event).data)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PermissionError as e:
            return Response({"error": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def patch(self, request, event_id):
        try:
            organization = self.get_organization(request)
            event = get_object_or_404(Event, id=event_id, organization=organization)
            data = request.data.copy()

            # Process image if present
            image_data = data.pop('image', None)
            try:
                if image_data:
                    image_file = self.process_image(image_data)
                    if event.image:
                        event.image.delete(save=False)
                    data['image'] = image_file
            except ValueError as e:
                return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

            serializer = EventSerializer(event, data=data, partial=True, context={'request': request})
            if serializer.is_valid():
                updated_event = serializer.save()
                return Response(EventSerializer(updated_event).data)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except PermissionError as e:
            return Response({"error": str(e)}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, event_id):
        try:
            organization = self.get_organization(request)
            event = get_object_or_404(Event, id=event_id, organization=organization)
            if event.image:
                event.image.delete()
            event.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except PermissionError as e:
            return Response({"error": str(e)}, status=status.HTTP_403_FORBIDDEN)

# New view for public access to events
class PublicEventView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can view events

    def get(self, request, event_id=None):
        try:
            if event_id:
                event = get_object_or_404(Event, id=event_id, status='published')
                return Response(EventSerializer(event).data)

            # Get all published events
            events = Event.objects.filter(status='published')
            return Response(EventSerializer(events, many=True).data)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class PublicAnnouncementView(APIView):
    permission_classes = [IsAuthenticated]  # Only authenticated users can view announcements

    def get(self, request):
        """
        Retrieve announcements with type-specific filtering options.
        """
        try:
            announcement_type = request.query_params.get('type')
            queryset = Announcement.objects.filter(status='published')

            # Apply type filter if specified
            if announcement_type:
                queryset = queryset.filter(type=announcement_type)

            serializer = AnnouncementSerializer(queryset, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# Statistics of the application
class AdminAnalyticsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """Get comprehensive analytics for admin dashboard"""
        try:
            # Get the last 6 months for timeline analysis
            end_date = timezone.now()
            start_date = end_date - timedelta(days=180)

            # Monthly statistics
            monthly_stats = HelpRequest.objects.filter(
                created_at__range=(start_date, end_date)
            ).annotate(
                month=TruncMonth('created_at')
            ).values('month').annotate(
                projects=Count('project', distinct=True),
                financial=Count('id', filter=Q(request_type='financial')),
                technical=Count('id', filter=Q(request_type='technical')),
                total_requests=Count('id'),
                transactions=Sum(
                    Case(
                        When(
                            request_type='financial',
                            then=F('financialrequest__amount_requested')
                        ),
                        default=0,
                        output_field=FloatField(),
                    )
                )
            ).order_by('month')

            # Technical statistics
            technical_stat = TechnicalProposal.objects.filter(
                created_at__range=(start_date, end_date)
            ).annotate(
                month=TruncMonth('created_at')
            ).values('month').annotate(
                technical_proposal=Count('id'),
            ).order_by('month')

            # Financial statistics
            financial_stat = FinancialProposal.objects.filter(
                created_at__range=(start_date, end_date)
            ).annotate(
                month=TruncMonth('created_at')
            ).values('month').annotate(
                financial_proposal=Count('id'),
            ).order_by('month')

            # Merge results
            merged_stats = defaultdict(lambda: {'technical_proposal': 0, 'financial_proposal': 0, 'total_requests': 0})

            # Format month to "Month Year"
            def format_month(month):
                return month.strftime('%b %y')

            # Add technical stats
            for stat in technical_stat:
                formatted_month = format_month(stat['month'])
                merged_stats[formatted_month]['technical_proposal'] = stat['technical_proposal']

            # Add financial stats
            for stat in financial_stat:
                formatted_month = format_month(stat['month'])
                merged_stats[formatted_month]['financial_proposal'] = stat['financial_proposal']

            # Add total_request stats
            for stat in monthly_stats:
                formatted_month = format_month(stat['month'])
                merged_stats[formatted_month]['total_requests'] = stat['total_requests']

            # Overall statistics
            total_projects = Project.objects.count()
            total_financing = FinancialProposal.objects.filter(
                status='accepted'
            ).aggregate(
                total=Sum('investment_amount')
            )['total'] or 0

            technical_help = TechnicalProposal.objects.filter(
                #request_type='technical',
                status='accepted'
            ).count()

            financial_help = FinancialProposal.objects.filter(
                # request_type='technical',
                status='accepted'
            ).count()

            # Calculate success rate
            total_completed = HelpRequest.objects.filter(
                status='completed'
            ).count()
            total_requests = HelpRequest.objects.count()
            success_rate = (total_completed / total_requests * 100) if total_requests > 0 else 0

            # Year over year growth
            previous_year = HelpRequest.objects.filter(
                created_at__lt=start_date
            ).count()
            current_year = HelpRequest.objects.filter(
                created_at__range=(start_date, end_date)
            ).count()
            yoy_growth = ((current_year - previous_year) / previous_year * 100) if previous_year > 0 else 0

            # Sector distribution
            sector_counts = Project.objects.values('sector').annotate(
                value=Count('id')
            ).order_by('-value')

            # Convert sector codes to display names using dict comprehension
            sector_display_names = dict(Project.SECTOR_CHOICES)
            sector_data = [
                {
                    'name': sector_display_names.get(item['sector'], item['sector']),
                    'value': item['value']
                }
                for item in sector_counts
            ]

            # Format stats data
            stats_data = {
                'overview': {
                    'total_projects': {
                        'title': 'Projets Totaux',
                        'value': str(total_projects),
                        'change': f'+{yoy_growth:.1f}%',
                        'bgColor': 'bg-blue-50',
                        'textColor': 'text-blue-600'
                    },
                    'total_financing': {
                        'title': 'Montant Total des Financements proposé',
                        'value': f'{total_financing / 1000000:.1f}M FCFA',
                        'change': f'+{((total_financing - previous_year) / previous_year * 100):.1f}%' if previous_year > 0 else '+0%',
                        'bgColor': 'bg-green-50',
                        'textColor': 'text-green-600'
                    },
                    'technical_help': {
                        'title': 'Aide Technique Fournie',
                        'value': str(technical_help),
                        'change': f'+{((technical_help - previous_year) / previous_year * 100):.1f}%' if previous_year > 0 else '+0%',
                        'bgColor': 'bg-orange-50',
                        'textColor': 'text-orange-600'
                    },
                    'financial_help': {
                        'title': 'Aide Financiere Fournie',
                        'value': str(financial_help),
                        'change': f'+{((financial_help - previous_year) / previous_year * 100):.1f}%' if previous_year > 0 else '+0%',
                        'bgColor': 'bg-yellow-50',
                        'textColor': 'text-yellow-600'
                    },
                    'success_rate': {
                        'title': 'Taux de Réussite',
                        'value': f'{success_rate:.1f}%',
                        'change': '+5.2%',  # Calculate actual change if historical data is available
                        'bgColor': 'bg-purple-50',
                        'textColor': 'text-purple-600'
                    }
                },
                'monthly_stats': [
                    {
                        'month': stat['month'].strftime('%b %y'),  # Short month name
                        'projects': stat['projects'],
                        'financial': stat['financial'],
                        'technical': stat['technical'],
                        'transactions': float(stat['transactions'] or 0)
                    }
                    for stat in monthly_stats
                ],
                'proposal_stats': [
                        {'month': month, **data} for month, data in sorted(merged_stats.items())
                ],
                'sector_data': list(sector_data)
            }

            return Response(stats_data)

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )