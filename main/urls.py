from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from . import views
from .views import RegisterView, LoginView, LogoutView, UserManagementView, UserStatsView, AdminSignupView, \
    ProjectAPIView, ProjectUploadDocumentAPIView, ProjectUpdateStatusAPIView, HelpRequestAPIView, \
    HelpUpdateStatusAPIView, HelpProposalView, EntrepreneurProposalView, ContractAPIView, CollaborationAPIView, \
    ContractViewDownloadAPIView, AnnouncementAPIView, EventManagementView, PublicAnnouncementView, PublicEventView, \
    AdminAnalyticsAPIView, UserView, VerifyResetCodeView, RequestPasswordResetView, ResetPasswordView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),

    # Password reset URLs
    path('password/reset/request/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('password/reset/verify/', VerifyResetCodeView.as_view(), name='verify-reset-code'),
    path('password/reset/confirm/', ResetPasswordView.as_view(), name='reset-password'),

    #User setting
    path('user/profile/', UserView.as_view()),
    path('users/<int:user_id>/profile/', UserView.as_view()),

                  #Project
    # List and create projects
    path('projects/', ProjectAPIView.as_view(), name='project-list-create'),
    # Retrieve, update, or delete a specific project
    path('projects/<int:pk>/', ProjectAPIView.as_view(), name='project-detail'),
    # Upload a document for a specific project
    path('projects/<int:pk>/upload-document/', ProjectUploadDocumentAPIView.as_view(), name='project-upload-document'),
    # Update the status of a specific project
    path('projects/<int:pk>/update-status/', ProjectUpdateStatusAPIView.as_view(), name='project-update-status'),
    # Demand for help
    path('help-requests/', HelpRequestAPIView.as_view(), name='help_requests_create'),
    path('help-requests/<int:pk>/', HelpRequestAPIView.as_view(), name='help_request_detail'),
    path('help-requests/<int:pk>/update-status/', HelpUpdateStatusAPIView.as_view(), name='help-update-status'),
    path('help-requests/<int:pk>/accepted-amount/',HelpRequestAPIView.as_view(),name='help-request-accepted-amount'),

    #Help proposal
    path('proposals/<str:proposal_type>/', HelpProposalView.as_view(), name='help-proposals'),
    path('proposals/<str:proposal_type>/<int:pk>/', HelpProposalView.as_view(), name='help-proposal-detail'),

    # New entrepreneur routes
    path('entrepreneur/proposals/', EntrepreneurProposalView.as_view(), name='entrepreneur-proposals'),
    path('entrepreneur/proposals/<str:proposal_type>/', EntrepreneurProposalView.as_view(),name='entrepreneur-proposals-by-type'),
    path('entrepreneur/proposals/<str:proposal_type>/<int:pk>/', EntrepreneurProposalView.as_view(),name='entrepreneur-proposal-detail'),

    #Contracts and collaborations
    # Contract endpoints
    path('contracts/', ContractAPIView.as_view(), name='contract-list'),
    path('contracts/<str:proposal_type>/<int:proposal_id>/', ContractAPIView.as_view(),name='contract-detail'),
    path('contracts/<int:contract_id>/<str:action>/', ContractViewDownloadAPIView.as_view(), name='contract-view-download'),

    # Collaboration endpoints
    path('collaborations/', CollaborationAPIView.as_view(), name='collaboration-list'),

    #Announcement
    path('announcements/', AnnouncementAPIView.as_view(), name='announcements'),
    path('announcements/<int:pk>/', AnnouncementAPIView.as_view(), name='announcement-detail'),

    # Event
    path('events/', EventManagementView.as_view(), name='event-create'),
    path('events/<int:event_id>/', EventManagementView.as_view(), name='event-detail'),

    # Public announcement endpoints
    path('public/announcements/', PublicAnnouncementView.as_view(), name='public-announcements'),
    path('public/announcements/<int:pk>/', PublicAnnouncementView.as_view(), name='public-announcement-detail'),

    # Public event endpoints
    path('public/events/', PublicEventView.as_view(), name='public-events'),
    path('public/events/<int:event_id>/', PublicEventView.as_view(), name='public-event-detail'),

    #Admin sign up
    path('admin/signup', AdminSignupView.as_view(), name='admin-signup'),

    #Admin User management
    path('admin/users', UserManagementView.as_view(), name='admin-users'),
    path('admin/users/<int:user_id>', UserManagementView.as_view(), name='admin-user-update'),
    path('admin/users/stats', UserStatsView.as_view(), name='admin-user-stats'),
    path('admin/analytics/', AdminAnalyticsAPIView.as_view(), name='admin-analytics'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)