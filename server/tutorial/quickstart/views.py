from django.shortcuts import render
from django.contrib.auth.models import User, Group
from rest_framework import viewsets
import jwt,json
from django.shortcuts import render
from django.utils.safestring import mark_safe
from rest_framework.views import APIView
from rest_framework.parsers import JSONParser
from rest_framework.authtoken.views import ObtainAuthToken
from django.db.models import Q
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework import views
from django.contrib.auth.decorators import login_required
from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from rest_framework.response import Response
from django.template.loader import render_to_string
from rest_framework import generics,viewsets,mixins
from .models import User,PhoneOtp,Doctor
from rest_framework_jwt.settings import api_settings
from rest_framework.parsers import MultiPartParser, FormParser
from django.http import HttpResponse
from quickstart.serializers import *
from rest_framework.permissions import IsAuthenticated
from rest_framework import serializers
from rest_framework.decorators import api_view
from django.utils import timezone
from rest_framework import generics, mixins, permissions
from datetime import timedelta
from .models import Message
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import status,permissions
from rest_framework.decorators import action
from rest_framework.authtoken.models import Token
from django.core.mail import send_mail
from tutorial.settings import EMAIL_HOST_USER
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory
from random import *
from .models import PhoneOtp,Doctor,PhoneOtp,Appointment,Message,Rating,Enquiry,ReplyEnquiry,Category
from django.contrib.auth import authenticate, login
from rest_framework_jwt.views import obtain_jwt_token
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER
import random
from datetime import datetime
from django.contrib.auth import get_user_model
factory = APIRequestFactory()
request = factory.get('/')
User = get_user_model()

class UserViewSet(viewsets.ModelViewSet):
    queryset=User.objects.filter(street_name__isnull=True)
    serializer_class = UserSerializer2

    def get(self,request,format=None):
        users = User.objects.all()
        serializer = UserSerializer1(users, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = UserSerializer1(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SignUp(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class =UserSerializer1
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer1(data = request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        first_name = serializer.validated_data['first_name']
        last_name = serializer.validated_data['last_name']
        confirm_password = serializer.validated_data['confirm_password']
        user = User.objects.create_user(username=username,password=password,first_name=first_name,last_name=last_name,confirm_password=confirm_password)
        otp = randint(999,9999)
        data = PhoneOtp.objects.create(otp=otp,receiver=user)
        data.save()
        user.is_active = False
        user.save()
        subject = 'Activate Your Account'
        message = render_to_string('quickstart/accountactivate.html', {
            'user': user,
            'OTP': otp,
         })
        from_mail = EMAIL_HOST_USER
        to_mail = [user.username]
        send_mail(subject, message, from_mail, to_mail, fail_silently=False)
        return Response({'details': 'Please confirm your otp to complete registration.',
                               'user_id': user.id})

class validateotp(APIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = PhoneOtpSerializer

    def post(self,request,user_id,*args,**kwargs):
        otp_verify =  PhoneOtpSerializer(data = request.data)
        otp_verify.is_valid(raise_exception=True)
        otp_verify = otp_verify.validated_data['otp'] 
        try:
            otp = PhoneOtp.objects.get(receiver=user_id)
        except(TypeError, ValueError, OverflowError, PhoneOtp.DoesNotExist):
                otp = None
        try:
            receiver = User.objects.get(id=user_id)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            receiver = None
        if otp is None or receiver is None:
            return Response({'error':'you are not a valid user'},status=status.HTTP_400_BAD_REQUEST)

        elif timezone.now() - otp.sent_on >= timedelta(days=0,hours=0,minutes=2,seconds=0):
            otp.delete()
            return Response({'detail':'OTP expired!',
                                 'user_id':user_id})
        if otp.otp == otp_verify:
            receiver.is_active = True
            receiver.save()
            otp.delete()
            return Response({'message': 'Thank you for otp Verification you are successfully logged in'},
                            status=status.HTTP_200_OK)
        else: 
            return Response({'error':'Invalid OTP',})

class resendotp(generics.CreateAPIView):
    permission_classes = (permissions.AllowAny,)
    serializer_class = PhoneOtpSerializer
    def get(self,request,user_id,*args,**kwargs):
        try:
            user = User.objects.get(id=user_id)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None
        if user is None:
            return Response({'error':'Not a valid user!'})
        otp = PhoneOtp.objects.filter(receiver=user)
        if otp:
            otp.delete()
        otp = randint(999, 9999)
        data = PhoneOtp.objects.create(otp=otp,receiver= user)
        data.save()
        subject = 'Activate Your Account'
        message = render_to_string('quickstart/accountactivate.html', {
            'user': user,
            'OTP': otp,
        })
        from_mail = EMAIL_HOST_USER
        to_mail = [user.username]
        send_mail(subject, message, from_mail, to_mail, fail_silently=False)
        return Response({'details': user.username +',Please confirm your otp to complete registration.',
                         'user_id': user_id },
                        status=status.HTTP_201_CREATED)

class Sign_Up_Hospital(APIView):
    # permission_classes = (permissions.AllowAny,)
    # parser_classes = (MultiPartParser, FormParser)
    serializer_class = UserSerializer2
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer2(data = request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data['username']
        hospital_name = serializer.validated_data['hospital_name']
        # email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        confirm_password = serializer.validated_data['confirm_password']
        image = serializer.validated_data['image']
        street_name=serializer.validated_data['street_name']
        # rating=serializer.validated_data['rating']
        user = User.objects.create_user(username=username,hospital_name=hospital_name,image=image,password=password,confirm_password=confirm_password,street_name=street_name)
        otp = randint(999,9999)
        data = PhoneOtp.objects.create(otp=otp,receiver=user)
        data.save()
        user.is_active = False
        user.save()
        subject = 'Activate Your Account'
        message = render_to_string('quickstart/accountactivate.html', {
            'user': user,
            'OTP': otp,
         })
        from_mail = EMAIL_HOST_USER
        to_mail = [user.username]
        send_mail(subject, message, from_mail, to_mail, fail_silently=False)
        return Response({'details': 'Please confirm your otp to complete registration.',
                               'user_id': user.id})

# class JSONWebTokenAPIView(APIView):
#     """
#     Base API View that various JWT interactions inherit from.
#     """
    
#     # permission_classes = ()
#     # authentication_classes = ()
#     def get_serializer_context(self):
#         """
#         Extra context provided to the serializer class.
#         """
#         return {
#             'request': self.request,
#             'view': self,
#         }

#     def get_serializer_class(self):
#         assert self.serializer_class is not None, (
#             "'%s' should either include a `serializer_class` attribute, "
#             "or override the `get_serializer_class()` method."
#             % self.__class__.__name__)
#         return self.serializer_class

#     def get_serializer(self, *args, **kwargs):
#         serializer_class = self.get_serializer_class()
#         kwargs['context'] = self.get_serializer_context()
#         return serializer_class(*args, **kwargs)

#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         print("hellllllloooo")
#         if serializer.is_valid():
#             user = serializer.object.get('user') or request.user
#             token = serializer.object.get('token')
#             id = serializer.object.get('user_id')
#             response_data = jwt_response_payload_handler(token, user, id,request)
#             response = Response(response_data)
#             if api_settings.JWT_AUTH_COOKIE:
#                 expiration = (datetime.utcnow() +
#                               api_settings.JWT_EXPIRATION_DELTA)
#                 response.set_cookie(api_settings.JWT_AUTH_COOKIE,
#                                     token,
#                                     expires=expiration,
#                                     httponly=True)
#             return response

#         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# class ObtainJSONWebToken(JSONWebTokenAPIView):
#     serializer_class = JSONWebTokenSerializer

# class MySpecialJWT(ObtainJSONWebToken):
#     def post(self, request, *args, **kwargs):
#         response = super().post(request, *args, **kwargs)
#         # foo bar
#         return response
# obtain_jwt_token = ObtainJSONWebToken.as_view()

class HospitalViewSet(viewsets.ModelViewSet):
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    
    queryset = User.objects.filter(street_name__isnull=False)
    serializer_class = UserSerializer2
    def get(self,request,*args,**kwargs):
        users = User.objects.all()
        serializer = UserSerializer2(users, many=True)
        return Response(serializer.data)
    def post(self, request, *args,**kwargs):
        serializer = UserSerializer2(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DoctorView(APIView):
    # permission_classes = (permissions.IsAuthenticatedOrReadOnly,)
    serializer_class = DoctorSerializer
    
    # def get(self,request,*args,**kwargs):
    #     username =self.request.user
    #     doctor = Doctor.objects.filter(hospital__username=username)
    #     serializer = DoctorSerializer(doctor, many=True)
    #     return Response(serializer.data)
    def post(self,request,*args,**kwargs):
        user = request.user
        # hospital = Doctor.objects.get(hospital = user.id)
        serializer = DoctorSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class HospitalProfile(APIView):
    def get(self,request,*args,**kwargs):
        user = request.user
        doctor = Doctor.objects.filter(username=user)
        serializer = DoctorSerializer(data=doctor, many=True)
        serializer.is_valid()
        return Response(serializer.data)
    # def post(self,request,user_id,*args,**kwargs):
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data, status=status.HTTP_201_CREATED)
    #     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class HospitalDoctor(APIView):
    serializer_class= DoctorSerializer
    def get(self,request,username,*args,**kwargs):
        user = User.objects.get(username = username)
        doctor = Doctor.objects.filter(hospital = user.id)
        serializer = DoctorSerializer(data = doctor, many = True)
        serializer.is_valid()
        return Response(serializer.data)

class HospitalDoctors(APIView):
    serializer_class= DoctorSerializer
    def get(self,request,user_id, *args,**kwargs):
        doctor = Doctor.objects.filter(hospital = user_id)
        serializer = DoctorSerializer(data = doctor, many = True)
        serializer.is_valid()
        return Response(serializer.data)

class MessageView(APIView):
    def get(self,request,*args,**kwargs):
        message = Message.objects.all()
        serializer = MessageSerializer(message,many=True)
        return Response(serializer.data)
    def post(self, request, *args,**kwargs):
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Hospital_Name(APIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = UserSerializer2
    def get(self,request,user_id,*args,**kwargs):
        user= User.objects.get(id = user_id)
        serializer =  UserSerializer2(user)
        return Response(serializer.data)

class Make_Enquiry(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = EnquirySerializer
    def post(self, request, *args,**kwargs):
        serializer = EnquirySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ReplyEnquiryView(APIView):
    # permission_classes = [permissions.AllowAny]
    serializer_class = ReplySerializer
    def post(self,request, *args,**kwargs):
        enquiry=Enquiry.objects.get(id=self.kwargs['id'])
        enquiry.delete()
        serializer = ReplySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EnquiryView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request,*args,**kwargs):
        user = self.request.user
        enquiry = Enquiry.objects.filter(hospital_name__username = user)
        serializer = EnquirySerializer(enquiry, many=True)
        return Response(serializer.data)

class Patient_EnquiryView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, *args,**kwargs):
        enquiry =  ReplyEnquiry.objects.filter(username = self.request.user)
        serializer = ReplySerializer(enquiry, many=True)
        return Response(serializer.data)

class DeleteEnquiry(APIView):
   def post(self, request,enquiry_id, *args,**kwargs):
        serializer = ReplySerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class Make_Appointment(APIView):
    serializer_class = AppointmentSerializer
    def post(self,request,doctor_id,*args,**kwargs): 
        serializer = AppointmentSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data.get('username')
            appointment1 = Appointment.objects.filter(username = user)
            appointments = appointment1.filter(doctor = doctor_id)
            for appointment in appointments:
                print(appointment.status)
                if(appointment.status == None):
                    return Response("You have already applied for the appointment")
                # elif(i.status == "accept"):
                #     return Response("You appointment is already accepted")
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AppointmentView(APIView):
    def get(self,request,doctor_id,*args,**kwargs):
        doctor = Appointment.objects.filter(doctor = doctor_id)
        serializer = AppointmentSerializer(doctor, many=True)
        return Response(serializer.data)

class AppointmentReply(APIView):
    serializer_class = AppointmentSerializer
    def post(self,request,appointment_id,*args,**kwargs):
        cu_status = self.kwargs['cu_status']
        appointment = Appointment.objects.get(id = appointment_id)
        appointment.status = cu_status
        appointment.save()
        print(appointment_id)
        print(type(appointment.status))
        serializer = AppointmentSerializer(data=request.data)
        # data = serializer.data
        if serializer.is_valid():
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AppointmentProfileView(APIView):
    serializer_class = AcceptRejectAppointmentSerializer
    def get(self,request,*args,**kwargs):   
        status = self.kwargs['status']
        if status == 'accept':
            return Response({'Your appointment has been approved'})
        elif status == 'reject':
            return Response({'Your appointment has been cancelled'})
 
class UserProfileChangeAPIView(generics.RetrieveAPIView,
                               mixins.DestroyModelMixin,
                               mixins.UpdateModelMixin):
    
    serializer_class = UserProfileChangeSerializer
    # parser_classes = (MultiPartParser, FormParser,)

    def get_object(self):
        username = self.kwargs["username"]
        obj = get_object_or_404(User, username=username)
        return obj

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

class DoctorProfileChangeAPIView(APIView):
    
    serializer_class = doctorSerializer
    def get(self,request,doctor_id,*args,**kwargs):
        doct = Doctor.objects.get(id=doctor_id)
        serializer = doctorSerializer(doct)
        return Response(serializer.data)
    
    def post(self, request, doctor_id, *args,**kwargs):
        doctor = Doctor.objects.get(id = doctor_id)
        serializer = doctorSerializer(data=request.data)
        # data = serializer.da
        if serializer.is_valid():
            doctor.first_name = serializer.data.get('first_name')
            doctor.last_name = serializer.data.get('last_name')
            doctor.Years_of_Experience = serializer.data.get('Years_of_Experience')
            doctor.Qualification = serializer.data.get('Qualification')
            # doctor.Specialization= serializer.data.get('Specialization')
            doctor.Contact = serializer.data.get('Contact')
            # doctor.hospital = serializer.data.get('hospital')
            # doctor.image = serializer.data.get('image')
            if 'image' in request.FILES:           
                doctor.image=request.FILES['image']
                print(doctor.image)
                doctor.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserProfileChangeHospitalAPIView(generics.RetrieveAPIView,
                               mixins.DestroyModelMixin,
                               mixins.UpdateModelMixin):
    # permission_classes = (
    #     permissions.IsAuthenticated
        
    # )
    serializer_class = HospitalProfileChangeSerializer
    # parser_classes = (MultiPartParser, FormParser,)

    def get_object(self):
        username = self.kwargs["username"]
        obj = get_object_or_404(User, username=username)
        return obj

    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

def index(request):
    return render(request, 'quickstart/index.html', {})

@login_required
def room(request, room_name):
    return render(request, 'quickstart/room.html', {
        'room_name_json': mark_safe(json.dumps(room_name)),
        'username': mark_safe(json.dumps(request.user.username)),
    })
class HospitalRating(APIView):
    serializer_class = RatingSerializer
    def get_serializer_class(self):
        if self.action == 'submit_rating':
            return RatingSerializer

    @action(methods=['get'],detail=True)
    def rating(self,*args,**kwargs):
        hospital_id = self.kwargs['pk']
        all_rating = Rating.objects.all()
        total_rating = all_rating.count()
        avg_rating = 0
        rating_count = 0
        for rate in all_rating:
            rating_count += rate.star
        avg_rating = rating_count/(total_rating + 1)
        if not self.request.user.is_anonymous:
            try:
                rated = Rating.objects.get(user=self.request.user,hospital=hospital_id)
            except (Rating.DoesNotExist):
                rated =None
            if rated is None:
                return Response({'status':False,'avg_rating':avg_rating})
            return Response({'status':True,'avg_rating':avg_rating})
        else:
            return Response({'avg_rating':avg_rating})

    @action(methods=['POST'],detail=True)
    def submit_rating(self,request,*args,**kwargs):
        hospital_id = self.kwargs['pk']
        hospital = User.objects.get(id=hospital_id)
        try:
            rated = Rating.objects.get(user=self.request.user,hospital=hospital)
        except (Rating.DoesNotExist):
            rated =None
        if rated is None:
            rating = RatingSerializer(data=request.data)
            if rating.is_valid(raise_exception=True):
                rating.save(user=request.user,hospital=hospital)
                return Response("rated")
            return Response(status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class doctor(APIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = doctorSerializer
    def get(self,request,doctor_id,*args,**kwargs):
        doct = Doctor.objects.get(id=doctor_id)
        serializer = doctorSerializer(doct)
        return Response(serializer.data)

class Hospital_Profile(APIView):
    serializer_class = HospitalProfileChangeSerializer
    def get(self,request,*args,**kwargs):
        username = self.kwargs['username']
        user =User.objects.get(username=username)
        # print(user.id)
        print(user.email)
        return Response({'user_id':user.id,'User_email':user.email})

class DeleteDoctors(APIView):
    def delete(self, request, user_id, *args,**kwargs):
        doctor = Doctor.objects.get(id=id)
        doctor.delete()
        return Response(status=status.HTTP_204_NO_CONTENT) 

class doctor_by_category(APIView):
       def post(self, request, category_id, *args,**kwargs):
        category = Category.objects.get(id = category_id)
        doctor = Doctor.objects.filter(Specialization=category)
        serializer = DoctorSerializer(doctor,many=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class JSONWebTokenAPIView(APIView):
    """
    Base API View that various JWT interactions inherit from.
    """
    permission_classes = ()
    authentication_classes = ()

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'view': self,
        }

    def get_serializer_class(self):
        """
        Return the class to use for the serializer.
        Defaults to using `self.serializer_class`.
        You may want to override this if you need to provide different
        serializations depending on the incoming request.
        (Eg. admins get full serialization, others get basic serialization)
        """
        assert self.serializer_class is not None, (
            "'%s' should either include a `serializer_class` attribute, "
            "or override the `get_serializer_class()` method."
            % self.__class__.__name__)
        return self.serializer_class

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') 
            token = serializer.object.get('token')
            # street_name = serializer.object.get('street_name') 
            response_data = jwt_response_payload_handler(token, user, request)
            response = Response(response_data)
            if api_settings.JWT_AUTH_COOKIE:
                expiration = (datetime.utcnow() + 
                              api_settings.JWT_EXPIRATION_DELTA)
                response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                    token,
                                    expires=expiration,
                                    httponly=True)
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ObtainJSONWebToken(JSONWebTokenAPIView):
    serializer_class = JSONWebTokenSerializer

class MySpecialJWT(ObtainJSONWebToken):
    def post(self, request, *args, **kwargs):
        print("hellllooo")
        response = super().post(request, *args, **kwargs)
        # foo bar
        return response

obtain_jwt_token = ObtainJSONWebToken.as_view()