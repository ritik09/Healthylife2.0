from django.urls import re_path
from django.conf.urls import url
from . import consumers

websocket_urlpatterns = [
    url(r'ws/quickstart/(?P<room_name>\w+)/$', consumers.ChatConsumer),
]