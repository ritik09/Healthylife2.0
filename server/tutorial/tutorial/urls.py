"""tutorial URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from rest_framework.routers import DefaultRouter
from django.contrib import admin
from django.urls import include,path
from rest_framework import routers
from quickstart import views
from django.conf.urls import url
from rest_framework_jwt.views import obtain_jwt_token
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt import views as jwt_views
from quickstart.views import SignUp,validateotp,resendotp,MessageView,HospitalViewSet,DoctorView,HospitalProfile,HospitalDoctor,HospitalDoctors,MySpecialJWT
from django.contrib.auth.views import LoginView
from django_otp.forms import OTPAuthenticationForm
# from quickstart.views import CustomAuthToken
# from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView

router = routers.DefaultRouter()
router.register(r'users', views.UserViewSet)
router.register(r'hospitals',views.HospitalViewSet,basename='hospitals')
# router.register(r'hospitals_signup',views.Sign_Up_Hospital)
# router.register(r'^hospital_profile/(?P<user_id>[0-9]+)/$', views.HospitalProfile, basename='hospital_profile'),
# router.register(r'^hospital/(?P<user_id>[0-9]+)/$',views.DoctorView, basename='hospital'),
default_router = DefaultRouter(trailing_slash=False)


# router.register(r'login', views.LoginViewSet)

urlpatterns = [
    path('admin/', admin.site.urls),
    # url(r'^api-token-auth/', views.obtain_auth_token),    
    path('quickstart/',include('quickstart.urls')), 
    path('', include(router.urls)),
    url(r'^login/', MySpecialJWT.as_view()),
    path('login_as_hospital/', MySpecialJWT.as_view()),
    # path('hospital/',DoctorView.as_view(),name='hospital'),
    url(r'^hospital_doctors/(?P<user_id>[0-9]+)/$',HospitalDoctors.as_view(), name='hospital_profile'),
    url(r'^validateotp/(?P<user_id>[0-9]+)/$', validateotp.as_view(), name='validateotp'),
    # url(r'^validateotp_hospital/(?P<user_id>[0-9]+)/$', validateotp.as_view(), name='validateotp'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('',include(default_router.urls)),
    # url(r'^log/$',views.Login.as_view()),
    # path('api/token/', jwt_views.TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', jwt_views.TokenRefreshView.as_view(), name='token_refresh'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
