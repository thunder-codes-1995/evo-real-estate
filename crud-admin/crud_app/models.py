from django.db import models
import subprocess, os, jsonfield, threading, requests, json
from .utils import camel_case
import logging


logger = logging.getLogger(__name__)

group_list = (
    ('Seeders', 'Seeders'),
    ('Sales', 'Sales'),
    ('Post Sales', 'Post Sales'),
    ('Analytics', 'Analytics'),
    ('Common', 'Common')
)
    
Type = (
    ('textfield', 'textfield'),
    ('number', 'number'),
    ('select', 'select'),
    ('textarea','textarea'),
    ('checkbox','checkbox'),
    ('radio','radio'),
    ('date','date'),
    ('time','time'),
    ('user','user'),
)

ValidationType = (
    ('EmailStr', 'EmailStr'),
    ('phone', 'phone'),
    ('StrictBool', 'StrictBool'),
    ('PositiveInt', 'PositiveInt'),
    ('PositiveFloat', 'PositiveFloat'),
    ('StrictStr', 'StrictStr'),
    ('PastDatetime', 'PastDatetime'),
    ('FutureDatetime', 'FutureDatetime')
)

class BizApp(models.Model):
    name = models.CharField(max_length=155, unique=True)

    class Meta:
        verbose_name_plural = "Biz App"
    
    def __str__(self):
        return self.name

class Organization(models.Model):
    name = models.CharField(max_length=155, unique=True, db_index=True)

    class Meta:
        verbose_name_plural = "Organization"
    
    def __str__(self):
        return self.name
    
class Business(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT, null=False,blank=False, db_index=True)
    name = models.CharField(max_length=155, unique=True, db_index=True)
    logo = models.ImageField(default="pngegg.png",blank=True, null=True)
    business_code = models.CharField(max_length=156, unique=True, db_index=True)

    class Meta:
        verbose_name_plural = "Business"
    
    def save(self, *args, **kwargs):    
        self.business_code = (self.business_code).lower()
        obj = super().save(*args, **kwargs)      

    def __str__(self):
        return self.name
    
class Collection(models.Model):
    business_code = models.CharField(max_length=155, db_index=True)
    name = models.CharField(max_length=155)
    display_name = models.CharField(max_length=155, default="")
    is_seeder = models.BooleanField(default=False)
    have_library = models.BooleanField(default=False)
    group = models.CharField(max_length=50, default="Common")
    display_fields = jsonfield.JSONField(null=True, blank=True)
    action_fields = models.TextField(null=True, blank=True)
    state_machine_enable = models.BooleanField(default=False)
    additional_data = models.CharField(max_length=555,null=True, blank=True)
    is_archive = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = "Collections"

    def save(self, *args, **kwargs):    
        self.name = (self.name).lower()
        self.business_code = (self.business_code).lower()
        obj = super().save(*args, **kwargs)        
    
    def __str__(self):
        return self.name

class Seeder(models.Model):
    collection = models.ForeignKey(Collection, on_delete=models.CASCADE, null=False,blank=False, db_index=True)

    class Meta:
        verbose_name_plural = "Seeders"

    def __str__(self):
        return self.collection.name

class CollectionFields(models.Model):
    collection = models.ForeignKey(Collection, on_delete=models.PROTECT, null=False,blank=False, db_index=True)
    name = models.CharField(max_length=55, default=None,null=True,blank=False, db_index=True)
    type = models.CharField(max_length=50, choices=Type)
    seeder = models.ForeignKey(Seeder, on_delete=models.CASCADE, null=True,blank=True, db_index=True)
    required = models.BooleanField(default=True)
    validation_type = models.CharField(max_length=50, choices=ValidationType,null=True,blank=True)
    unique = models.BooleanField(default=False)
    display = models.BooleanField(default=False)
    sequence = models.DecimalField( max_digits = 5, default=1, decimal_places = 4)
    field_desc = models.TextField(null=True,blank=True)
    display_name = models.CharField(max_length=220, null=True,blank=True)
    
    class Meta:
        verbose_name_plural = "Collection Fields"
    
    # def has_delete_permission(self, request, obj=None):
    #     return True
            
    def save(self, *args, **kwargs):    
        self.name = (self.name).replace(" ","_")
        if self.type == 'seeder' or self.type == 'collection':
            self.type = 'select'
        super().save(*args, **kwargs)
    
    def update(self, *args, **kwargs):  
        self.name = (self.name).replace(" ","_")
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name
    

class Analytics(models.Model):
    business = models.ForeignKey(Business, on_delete=models.PROTECT, null=False,blank=False)
    label = models.CharField(max_length=155, unique=True)
    endpoint = models.CharField(max_length=155)

    class Meta:
        verbose_name_plural = "Analytics"
    
    def __str__(self):
        return self.label