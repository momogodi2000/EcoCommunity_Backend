# permissions.py
from rest_framework import permissions


class IsProposalOwnerOrRequestEntrepreneur(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        # Investor can only view/edit their own proposals
        if hasattr(request.user, 'investor'):
            return obj.investor == request.user.investor

        # Entrepreneur can view proposals on their requests
        if hasattr(request.user, 'entrepreneur'):
            return obj.help_request.entrepreneur == request.user.entrepreneur

        return False