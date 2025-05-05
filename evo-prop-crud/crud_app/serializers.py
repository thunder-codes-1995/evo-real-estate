from rest_framework import serializers
from crud_app.models import *


class CollectionSerializer(serializers.ModelSerializer):
  class Meta:
    model = Collection
    fields = '__all__'
    depth = 2

class CollectionFieldsSerializer(serializers.ModelSerializer):
  class Meta:
    model = CollectionFields
    fields = '__all__'
    depth=3

class SeederSerializer(serializers.ModelSerializer):
    collection = CollectionSerializer()
    collection_fields = CollectionFieldsSerializer(many=True, read_only=True)

    class Meta:
        model = Seeder
        fields = '__all__'

class BusinessSerializer(serializers.ModelSerializer):
  class Meta:
    model = Business
    fields = '__all__'
    depth=2

class BizAppSerializer(serializers.ModelSerializer):
  class Meta:
    model = BizApp
    fields = '__all__'
    depth=2

class OrganizationSerializer(serializers.ModelSerializer):
  class Meta:
    model = Organization
    fields = '__all__'
    depth=3