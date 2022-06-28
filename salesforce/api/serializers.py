import re
from .models import UserModel
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

class UserModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ['user_id', 'user_name']
        
