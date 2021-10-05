from rest_framework import permissions
from .models import *


class IsUser(permissions.BasePermission):

    def has_permission(self, request, view):
        user=User.objects.filter(user=self.request.user)
        if user and user.is_active==False:
            return True
        else:
            return False


class IsNotActive(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.user.is_active == True:
            return False
        return True

class IsOwnerOrReadOnly(permissions.BasePermission):

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.user.username == request.user.username

