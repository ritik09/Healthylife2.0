from django.db import models
from django.core.validators import MinLengthValidator
from django.contrib.auth.models import AbstractUser
import uuid
from django.core.validators import RegexValidator
from django.utils import timezone
from django.utils.encoding import python_2_unicode_compatible

def nameFile(instance, filename):
    return '/'.join(['images', str(instance.name), filename])

class User(AbstractUser):
    username=models.CharField(max_length=200, unique = True)
    hospital_name = models.CharField(max_length=100,null = True)
    # email=models.EmailField(max_length=200,help_text='Required')
    first_name=models.CharField(max_length=200)
    last_name=models.CharField(max_length=200)
    password=models.CharField(validators=[RegexValidator(regex='^.{6}$', message='Length has to be 6', code='nomatch')],max_length=50) 
    confirm_password=models.CharField(validators=[RegexValidator(regex='^.{6}$', message='Length has to be 6', code='nomatch')],max_length=50,null=True)
    image =models.ImageField(upload_to='static',null='True')
    street_name = models.CharField(max_length=100,null=True)    
    rating = models.IntegerField(null = True, blank = True)

class Meta:
    verbose_name =('user')
    verbose_name_plural = ('users')
    # abstract=True

    def _str_(self):
        return self.username

class PhoneOtp(models.Model):
    receiver = models.OneToOneField(User, on_delete=models.CASCADE,null=True)
    otp = models.IntegerField(null=False,blank=False)
    sent_on= models.DateTimeField(auto_now_add=True,null=True)

class Category(models.Model):
    cateory =  models.CharField(max_length=100)

class Doctor(models.Model):
    first_name = models.CharField(max_length=100,null=True)
    last_name = models.CharField(max_length=100,null=True)
    Qualification = models.CharField(max_length=100)
    Years_of_Experience = models.IntegerField()
    Specialization = models.ForeignKey(Category,on_delete=models.CASCADE,null=True)
    Contact = models.IntegerField()
    image = models.ImageField(upload_to='static',null='True')
    hospital = models.ForeignKey(User,on_delete=models.CASCADE,null=True)


class Rating(models.Model):
    user = models.ForeignKey(Doctor,on_delete=models.CASCADE)
    star = models.IntegerField()
    
    def __str__(self):
        return "%s rated %s"%(self.user.username,self.product.name)

class Enquiry(models.Model):
    username = models.CharField(max_length=100)
    contact=models.CharField(max_length=10,null=True)
    Query = models.TextField(max_length=300)
    hospital_name = models.ForeignKey(User,on_delete=models.CASCADE,null=True)

class ReplyEnquiry(models.Model):
    enquiry=models.CharField(max_length=500,null=True)
    reply = models.CharField(max_length=500)
    username = models.CharField(max_length=100,null=True)
    hospital_name = models.ForeignKey(User,on_delete=models.CASCADE,null=True)

class Message(models.Model):
    author = models.ForeignKey(User,related_name='author_messages',on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    reciever = models.ForeignKey(User,on_delete=models.CASCADE,null=True)

    def __str__(self):
        return self.author.username

    def last_30_messages(self):
        return Message.objects.order_by('-timestamp').all()[:30]

class Appointment(models.Model):
    username = models.CharField(max_length=100)
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE,null=True)
    status = models.CharField(max_length = 100, null = True)
    # contact = models.CharField(max_length=15)
    # first_name = models.CharField(max_length=100)
    # last_name = models.CharField(max_length=100,null=True)
    # hospital_name = models.ForeignKey(User,on_delete=models.CASCADE)

class AppointmentType(models.Model):
    Accepted = models.BooleanField(default=False)
    Rejected = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)






    