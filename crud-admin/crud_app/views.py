from django.shortcuts import redirect
from django.http import JsonResponse
import os, requests, logging, urllib3
from .serializers import *
from .models import *
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView

from django.db.models.signals import post_save
from django.dispatch import receiver

#for auto creation of models
from datetime import datetime
from git import Repo, GitCommandError
from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse

#For Atomicity
from django.db import transaction

#for elastic search
from elasticsearch import Elasticsearch
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#caching
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

logger = logging.getLogger(__name__)

fast_api_server = settings.CD_SERVICES_SERVER_URL
sso_api_server = settings.CD_SSO_SERVER_URL
dynamic_fast_api_server = settings.CD_DYNAMIC_SERVICES_SERVER_URL


#Verify authentication
def verify_authentication(request):
    authorization_header = request.headers.get('Authorization')
    sso_response = requests.get(sso_api_server+"/api/auth/user/crud/", headers={'Authorization': authorization_header})
    try:
        sso_response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        # Handle HTTP errors
        return False

    sso_response_json = sso_response.json()

    if sso_response_json['message'] == 'success':
        return sso_response_json['result']
    else:
        return False


#For incrementing git tag version
def increase_version(version_str, part_to_increase):
    # Split the version string into parts
    parts = list(map(int, version_str.split('.')))

    # Increment the specified part
    parts[part_to_increase] += 1

    # Convert the parts back to a string
    new_version = '.'.join(map(str, parts))

    return new_version


def index(request):
    data = {"message": "OK", "result": {}}
    return HttpResponse(content=json.dumps({'result': data}), content_type='application/json', status=200)

@receiver(post_save, sender=Collection)
def my_handler(sender, **kwargs):
    last_record = Collection.objects.all().order_by('-id').first()
    if last_record.is_seeder:
        Seeder.objects.update_or_create(collection_id=last_record.id)


def service_generator(request, collection, business_code):

    try:
        is_verified = verify_authentication(request)
        user_id = is_verified['user_id']
    except:
        data = {"message":"Unauthorized","result":{}}
        return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)


    elastic_user = settings.CD_ELASTIC_USER
    elastic_secret = settings.CD_ELASTIC_SECRET
    crud_server_url = settings.CD_CRUD_SERVER_URL
    sso_server_url = settings.CD_SSO_SERVER_URL
    elastic_host = settings.CD_ELASTIC_HOST
    elastic_port = settings.CD_ELASTIC_PORT
    dynamic_fast_api_server = settings.CD_DYNAMIC_SERVICES_SERVER_URL



    url = 'http://'+str(elastic_user)+':'+str(elastic_secret)+'@'+elastic_host+':'+elastic_port
    es = Elasticsearch(url, verify_certs=False)


    #This function will create a FAST API app and ba dynamic schema model.py with route.py
    collection = collection.lower()

    if business_code and collection:
        collection_obj = Collection.objects.filter(business_code__iexact=business_code).filter(name__iexact=collection)
    else:
        collection_obj = Collection.objects.filter(business_code__iexact=business_code)

    serializer = CollectionSerializer(collection_obj, many=True)

    for x in serializer.data:
        action_fields = []

        x['create_end_point']= dynamic_fast_api_server+'/'+str(collection)+'/create'
        x['list_end_point']= dynamic_fast_api_server+'/'+str(collection)+'/list'
        x['update_end_point']= dynamic_fast_api_server+'/'+str(collection)+'/update'

        collection_id = x['id']
        collection_fields = CollectionFields.objects.filter(collection_id=collection_id).order_by('sequence')
        field_serializer = CollectionFieldsSerializer(collection_fields, many=True)
        field_list = []
        # x['collection_fields']=field_serializer.data

        for field in field_serializer.data:
            if field['seeder'] is not None:
                collection_fields_ext = CollectionFields.objects.filter(collection_id=field['seeder']['collection']['id']).order_by('sequence')
                field_serializer_ext = CollectionFieldsSerializer(collection_fields_ext, many=True)
                field['seeder']['collection_fields'] = field_serializer_ext.data
                field['seeder']['create_end_point']= dynamic_fast_api_server+'/'+str(field['seeder']['collection']['name'])+'/create'
                field['seeder']['list_end_point']= dynamic_fast_api_server+'/'+str(field['seeder']['collection']['name'])+'/list'
                field['seeder']['update_end_point']= dynamic_fast_api_server+'/'+str(field['seeder']['collection']['name'])+'/update'

            field_list.append(field)

        x['collection_fields'] = field_list

        if x['action_fields'] is not None:
            for xy in (x['action_fields']).split(","):
                temp = {
                    "field":xy,
                    "list_end_point":dynamic_fast_api_server+'/'+xy+'/list',
                    "create_end_point":dynamic_fast_api_server+'/'+xy+'/create',
                    "update_end_point":dynamic_fast_api_server+'/'+xy+'/update'
                }
                action_fields.append(temp)

        x['action_fields'] = action_fields


    collection_json = serializer.data

    model_fields = ""
    model_fields_extra = ''
    unique_fields = False
    field_desc=""
    try:
        is_seeder = collection_json[0]['is_seeder']
    except:
        is_seeder = False
    state_machine_enable = collection_json[0]['state_machine_enable']
    additional_data = ''
    today_date = datetime.now().strftime('%Y-%m-%d')
    today_time = datetime.now().strftime('%H-%M-%S')

    try:
        additional_data = collection_json[0]['additional_data']
    except:
        pass

    for collection_f in collection_json[0]['collection_fields']:

        name = (collection_f['name']).replace(" ","_")
        type = collection_f['type']
        required = collection_f['required']
        validation_type = collection_f['validation_type']
        field_desc = collection_f['field_desc']
        if field_desc is None:
            field_desc = ""
        regex = ''
        if validation_type:
            if validation_type == 'email':
                regex = "regex=r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', "

        else:
            if type == 'number':
                type_m = 'float'
            else:
                if required:
                    type_m = 'str'
                else:
                    type_m = 'Optional[str]'
                    regex = '"",'

        if collection_f['unique']:
            unique_fields = True
        model_fields +='''
'''+'''    '''+ name+': '+type_m+' = Field('+str(regex)+' description="'+str(field_desc)+'",uniqueItems='+str(unique_fields)+')'
        model_fields_extra = model_fields_extra +'''
'''+'''                "'''+ name+'": "",'''

    #New code for code generator

    temp_folder_path = "/data/temp/dynamic_services/backend/apps/"
    # Path to the new folder
    business_folder_path = os.path.join(temp_folder_path, business_code)
    collection_folder_path = os.path.join(temp_folder_path+business_code, collection)
    print(collection_folder_path)
    print(business_folder_path)
    #TBD - try/catch
    temp_dynamic_folder_path = "/data/temp/dynamic_services/"
    print(temp_dynamic_folder_path)
    #main.py path
    # Create a new business folder
    os.makedirs(business_folder_path, exist_ok=True)

    # Create a new collection folder
    os.makedirs(collection_folder_path, exist_ok=True)

    # Path to the new models file inside the collection folder
    models_file_path = os.path.join(collection_folder_path, "models.py")

    # Path to the new routers file inside the collection folder
    routers_file_path = os.path.join(collection_folder_path, "routers.py")

    # Path to the new routers file inside the collection folder
    main_file_path = os.path.join(temp_dynamic_folder_path+'backend/', "dmain.py")

    # Fetch changes from the remote repository

    repo = Repo(temp_dynamic_folder_path)  # Initialize the Git repository object
    origin = repo.remote(name='origin')
    origin.fetch()
    try:
        origin.pull()
    except GitCommandError as e:
        print(f"Git command error: {e.stderr}")
        raise e

    try:
        collection_index=str(business_code)+"."+collection.lower()
        # resp = es.index(index=collection_index, id=1, document={})
    except:
        pass

    # Create a new models file inside the collection folder
    with open(models_file_path, 'w') as f1:
        f1.write('''\
from typing import Optional
import uuid
from pydantic import BaseModel, Field, Json
from typing   import Optional, List
from fastapi  import FastAPI, Form, File, UploadFile, Path, Query
from pydantic_settings import BaseSettings
from datetime import datetime, timedelta
from typing import Union
from uuid import UUID  

                       
class '''+collection+'''Model(BaseModel):
    created_by: Optional[str] = Field(None)
    created_at: str = Field(default_factory=lambda: (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S'))
    modified_by: Optional[str]  = Field(None)
    modified_at: Optional[str]  = Field(default_factory=lambda: (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S'))
    assigned_to: Optional[str] = Field(None)
    archived_at: Optional[str]  = Field(default_factory=lambda: (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S'))
    archived_by: Optional[str]  = Field(None)
    is_archived: Optional[bool] = Field(False)
    active: Optional[bool] = Field(True)
    id: Union[UUID, str] = Field(default_factory=uuid.uuid4, alias="_id",uniqueItems=True)'''+model_fields+'''
    class Config:
        populate_by_name = True
        arbitrary_types_allowed=True
        json_schema_extra = {
            "example": {
                "id": "",'''+model_fields_extra+'''
            }
        }

class '''+collection+'''UpdateModel(BaseModel):
    created_by: Optional[str]  = Field(None)
    created_at: Optional[str]  = Field(default_factory=lambda: (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S'))
    modified_by: Optional[str]  = Field(None)
    assigned_to: Optional[str] = Field(None)
    archived_at: Optional[str]  = Field(default_factory=lambda: (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S'))
    archived_by: Optional[str]  = Field(None)
    is_archived: Optional[bool] = Field(False)
    active: Optional[bool] = Field(True)
    modified_at: Optional[str]  = Field(default_factory=lambda: (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S'))
    '''+model_fields+'''
    class Config:
        arbitrary_types_allowed=True
        allow_population_by_field_name = True
        schema_extra = {
            "example": {
                "id": "",'''+model_fields_extra+'''
            }
        }
''')

    # If the collection is 'leads', add the combined model
    if collection == 'newleads':
        with open(models_file_path, 'a') as f1:
            f1.write('''
from apps.ee.leadenquiry.models import leadenquiryModel

class ''' + collection + '''CombinedModel(BaseModel):
    lead: ''' + collection + '''Model
    enquiry_info: leadenquiryModel
''')


    # Create a new models file inside the collection folder
    with open(routers_file_path, 'w') as f2:
        f2.write('''\
import string
from typing import List
from fastapi import APIRouter, Body, Request, HTTPException, status, File, UploadFile, Query
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
import csv, json, codecs,uuid
from .models import '''+collection+'''Model,'''+collection+'''UpdateModel
import os, asyncio, requests, json
#for elastic search
import urllib3, uuid
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from datetime import datetime
from elasticsearch import Elasticsearch
from bson import ObjectId
from datetime import datetime, timedelta
import pandas as pd
from io import BytesIO

import environ
env = environ.Env()
environ.Env.read_env()

elastic_user = env("ELASTIC_USER")
elastic_secret = env("ELASTIC_SECRET")
crud_server_url = env("CRUD_SERVER_URL")
sso_server_url = env("SSO_SERVER_URL")
services_server_url = env("SERVICES_SERVER_URL")
email_web_page_url = env("EMAIL_WEB_PAGE_URL")

elastic_host = env("ELASTIC_HOST")
elastic_port = env("ELASTIC_PORT")

url = 'http://'+str(elastic_user)+':'+str(elastic_secret)+'@'+str(elastic_host)+':'+str(elastic_port)

es = Elasticsearch(url, verify_certs=False)

router = APIRouter()

#lead state logic
async def state_update(request, future_state, collection, id):

    existing_record = await request.app.mongodb[collection].find_one({"_id": id})
    existing_state = existing_record['status']    
    try:
        condition = [{"existing_state": existing_state},{"collection": collection}]
        record = await request.app.mongodb["state_machine"].find({
            "$and": condition
            }).to_list(length=20)
        
        future_states = []
        for r in record:
            future_states.append(r.get('future_state'))
        # Check if existing_state exists in future_states
        if future_state in future_states:
            return True
        else:
            return False
    except:
        return False

# Authentication Verify
def verify_authentication(request: Request):
    authorization_header = request.headers.get('Authorization')
    sso_response = requests.get(sso_server_url+"/api/auth/user/", headers={'Authorization': authorization_header})
    
    try:
        sso_response.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        # Handle HTTP errors
        return False

    sso_response_json = sso_response.json()
    print(sso_response_json)
    if sso_response_json['message'] == 'success':
        return sso_response_json['result']
    else:
        return False

#Helper function to write in activities
async def new_activity(request,activities_data):
    
    try:
        # Add a record in the "activities" collection
        activities_result = await request.app.mongodb["activities"].insert_one(activities_data)
        activities_inserted_id = activities_result.inserted_id
        return True
    except Exception as e:
        return False


# Helper function for building JSON responses
def build_response(status_code: int, result=None, message=None, count_query=None):
    """
    Build a standardized JSON response.

    Args:
        status_code (int): HTTP status code.
        result (dict): Result data.
        message (str): Response message.

    Returns:
        JSONResponse: Constructed JSON response.
    """
    if count_query is not None:
        data = {"count_query": count_query, "result": result, "message": message}
    else:
        data = {"result": result, "message": message}
    return JSONResponse(status_code=status_code, content=data)

# Helper function for preprocessing data
def preprocess_row(row):
    for key, value in row.items():
        if pd.isna(value):
            row[key] = None
        elif isinstance(value, (int, float)):
            row[key] = str(value)
    return row

def index_in_elastic(data,id,collection):
    business_code =  "'''+str(business_code)+'''"
    #Indexing a document
    # try:
    new_dic={}
    for k, v in data.items():
        if k=='_id':
            new_dic["id"]=v
        elif k=='created_at':
            # Specify the format of your date string
            date_format = "%Y-%m-%d %H:%M:%S"

            # Convert the string to a datetime object
            datetime_object = datetime.strptime(v, date_format)

            new_dic["created_at"] = datetime_object
        else:
            new_dic[k]=v

    doc = new_dic
    collection_index=business_code+"."+collection.lower()
    resp = es.index(index=collection_index, id=id, document=doc)
    if resp['_index']: 
        return True
    else:
        return False  

def send_email_request(lead_id: str, lead_name: str, lead_email: str, project_name: str, web_page: str):
    try:
        # Define the endpoint URL
        url = services_server_url+"/send_email/"

        # Define the payload for the request
        payload = {
            "lead_id": lead_id,
            "lead_name": lead_name,
            "lead_email": lead_email,
            "project_name": project_name,
            "web_page": web_page
        }

        # Send a POST request to the endpoint
        response = requests.post(url, json=payload)

        # Check if the request was successful (status code 200)
        if response.status_code == 202:
            print("email_resp: ", response.content)
            print("Email request successful!")
        else:
            print("Failed to send email. Status code: ", response.status_code)
            print(response.text)

    except requests.exceptions.RequestException as e:
        print("Request error: ", e)

@router.get("/PartialUpdate", response_description="Partial Update")
async def pupdate(request: Request, id: str, value: str, key: str):
    collection = "'''+collection+'''"
    business_code =  "'''+str(business_code)+'''"
    additional_data = "'''+str(additional_data)+'''"
    try:

        try:
            is_verified = request.state.is_verified       
            is_verified_permissions = json.loads(is_verified['permissions'])
        except:
            data = {"message":"Unauthorized","result":{}}
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

        have_permission = False

        # Permissions to check
        permissions_to_check = ["edit"]

        # Loop through the data structure
        for entry in is_verified_permissions:
            for collection_id, collection_data in entry.items():
            
                if collection_data["collection_name"] == collection:
                    # Check if any of the required permissions exist in the collection's permissions
                    has_permissions = any(permission in collection_data["permissions"] for permission in permissions_to_check)

                    if has_permissions:
                        have_permission = True
                
        if is_verified['user_id']:
            if have_permission:
                modified_by = is_verified['user_id']
                created_by = is_verified['user_id']
            else:
                data = {"message":"Forbidden","result":{}}
                return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
        else:
            data = {"message":"token invalid","result":{}}
            return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)

        created_by_filter = {"created_by": created_by}
        assigned_to_filter = {"assigned_to": created_by}

        filter_conditions = {"$or": [created_by_filter, assigned_to_filter, {"_id": id}]}
        
        #logic for state change 

        is_valid_state = True
        state_machine_enable = "'''+str(state_machine_enable)+'''"

        if key == 'status' and state_machine_enable:
            future_state = value
            is_valid_state = await state_update(request, future_state, collection, id)

        today_date = datetime.now().strftime('%Y-%m-%d')
        today_time = datetime.now().strftime('%H-%M-%S')

        # Updating a document
        if is_valid_state:
            if value == 'true' or value=='false':
                if value == 'true':
                    value=True
                if value == 'false':
                    value=False
            # update_result = await request.app.mongodb["'''+collection+'''"].update_one(filter_conditions, {"$set": {key: value, "modified_by": modified_by}})
            update_result = await request.app.mongodb["'''+collection+'''"].update_one({"_id": id}, {"$set": {key: value, "modified_by": modified_by}})
        else:
            return build_response(status.HTTP_406_NOT_ACCEPTABLE, result={}, message="not acceptable")
        try:
            data = {key: value}
            resp = es.update(index=business_code+"." + collection.lower(), id=id, doc=jsonable_encoder(data))
            activities_data = {
                    "title": "Record updated in "+str(collection),
                    "type":"Update",
                    "user_id": str(created_by),
                    "parent_doc_id": str(id),
                    "collection": str(collection),
                    "date":today_date,
                    "time":today_time,                
                    }
            await new_activity(request,activities_data)
        except:
            pass
        
        new_task = await request.app.mongodb[collection].find_one({"_id": id})

        additional_data = additional_data.split(",")
        
        # Append additional data from other collections       
        additional_data_list = {}
        for ad in additional_data:
            # Example: Append data from another collection
            additional_data_res = await request.app.mongodb[ad].find({"parent_doc_id": new_task['_id']}).sort([("date", -1)]).to_list(length=4)
            
            # Convert ObjectId to string in the additional_data_res
            for item in additional_data_res:
                if '_id' in item:
                    item['_id'] = str(item['_id'])

            if additional_data_res:
                additional_data_list.setdefault(ad, {})
                additional_data_list[ad]=additional_data_res
            else:
                additional_data_list.setdefault(ad, [])
            
        # Update the 'additional_data' key in the task with the modified list        
        new_task['additional_data'] = additional_data_list
        return build_response(status.HTTP_201_CREATED, result=new_task, message="success")
    except Exception as e:
        return build_response(status.HTTP_400_BAD_REQUEST, result={}, message=f"failed: {str(e)}")

@router.post("/import", response_description="Add new")
async def upload(request: Request, file: UploadFile = File(...)):
    try:
        try:
            is_verified = request.state.is_verified    
            is_verified_permissions = json.loads(is_verified['permissions'])
        except:
            data = {"message":"Unauthorized","result":{}}
            return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

        collection = "'''+collection+'''"
        user_id = is_verified['user_id']
        
        filename = file.filename
        file_extension = filename.split('.')[-1]


        form_data = await request.form()
        field_mappings = json.loads(form_data.get("fieldMappings"))
        agent_ids = []
        if collection in ['data', 'leads']:
            agent_ids = json.loads(form_data.get("agent_ids"))
        doc_ids = []
            
        print("*"*60)
        print(f"{file_extension=}")
        if file_extension == 'csv':
            csvReader = csv.DictReader(codecs.iterdecode(file.file, 'utf-8'))
            for row in csvReader:
                if field_mappings:
                    row = {field_mappings.get(key, key): value for key, value in row.items()}
                
                # Check for status and set default
                if 'status' not in row or not row['status']:
                    row['status'] = 'New'
                    
                model = '''+collection+'''Model.model_validate(row)
                task = jsonable_encoder(model)
                
                task['created_by'] = user_id
                task['modified_by'] = user_id
                task['assigned_to'] = user_id
    
                new_task = await request.app.mongodb[collection].insert_one(task)
    
                try:
                    doc_ids.append(new_task.inserted_id)
                    lead_data = await request.app.mongodb[collection].find_one({"_id": new_task.inserted_id})
                    # if new_task.inserted_id and lead_data['status']=='New' and lead_data['email'] and lead_data['name'] and lead_data['project_name']:
                    #     send_email_request(
                    #         lead_id=lead_data['_id'],
                    #         lead_name=lead_data['name'],
                    #         lead_email=lead_data['email'],
                    #         project_name=lead_data['project_name'],
                    #         web_page=email_web_page_url
                    #     )
                except Exception as e:
                    print("error: ", e)
    
                created_task = await request.app.mongodb[collection].find_one(
                    {"_id": new_task.inserted_id}
                )
                res = index_in_elastic(task, str(model.id), collection)
                
                if collection == 'leads':
                    try:
                        response = requests.post(
                            f"{services_server_url}/jobs/schedule",
                            headers={'Authorization': request.headers.get('Authorization')},
                            json={"lead_id": new_task.inserted_id}
                        )
                        if response.status_code == 200:
                            print("SLA jobs scheduled")
                        else:
                            print(f"SLA job API failed. Reason {response.text}")
                    except Exception as e:
                        print(f"Failure while scheduling SLA jobs. Exception: {e}")
        
        elif file_extension == 'xlsx':
            content = await file.read()
            # df = pd.read_excel(BytesIO(content), skiprows=1)
            df = pd.read_excel(BytesIO(content), header=None)
            df.columns = df.iloc[0]  # Set the first row as header
            df = df[1:].reset_index(drop=True)  # Remove the first row from the data
            for _, row in df.iterrows():
                row = preprocess_row(row.to_dict())
                print("-"*60)
                print(f"{row=}")
                print("-"*60)
                if field_mappings:
                    row = {field_mappings.get(key, key): value for key, value in row.items()}
                
                # Check for status and set default
                if 'status' not in row or not row['status']:
                    row['status'] = 'New'    
                
                model = '''+collection+'''Model.model_validate(row)
                task = jsonable_encoder(model)

                task['created_by'] = user_id
                task['modified_by'] = user_id
                task['assigned_to'] = user_id

                new_task = await request.app.mongodb[collection].insert_one(task)
                try:
                    doc_ids.append(new_task.inserted_id)
                    lead_data = await request.app.mongodb[collection].find_one({"_id": new_task.inserted_id})
                    # if new_task.inserted_id and lead_data['status']=='New' and lead_data['email'] and lead_data['name'] and lead_data['project_name']:
                        # send_email_request(
                        #     lead_id=lead_data['_id'],
                        #     lead_name=lead_data['name'],
                        #     lead_email=lead_data['email'],
                        #     project_name=lead_data['project_name'],
                        #     web_page=email_web_page_url
                        # )
                except Exception as e:
                    print("error: ", e)
                
                created_task = await request.app.mongodb[collection].find_one(
                    {"_id": new_task.inserted_id}
                )
                res = index_in_elastic(task, str(model.id), collection)

            if collection == 'leads':
                try:
                    response = requests.post(
                        f"{services_server_url}/jobs/schedule",
                        headers={'Authorization': request.headers.get('Authorization')},
                        json={"lead_id": new_task.inserted_id}
                    )
                    if response.status_code == 200:
                        print("SLA jobs scheduled")
                    else:
                        print(f"SLA job API failed. Reason {response.text}")
                except Exception as e:
                    print(f"Failure while scheduling SLA jobs. Exception: {e}")

        file.file.close()
        
        if collection in ['data', 'leads'] and agent_ids and doc_ids:
            user_count = len(agent_ids)
    
            for i, doc_id in enumerate(doc_ids):
                # Use modulo to repeat user IDs when doc IDs exceed user IDs
                agent_id = agent_ids[i % user_count]
                result = await request.app.mongodb[collection].update_one(
                    {"_id": doc_id},  # Match the document by its ID
                    {"$set": {"assigned_to": agent_id}}  # Update or add the `assigned_to` field
                )

        return build_response(status.HTTP_201_CREATED, result={}, message="success")
    except Exception as e:
        return build_response(status.HTTP_400_BAD_REQUEST, result={}, message=f"failed: {str(e)}")
       
        
@router.post("/create", response_description="Add new")
async def create(request: Request, task: '''+collection+'''Model = Body(...)):
    # try:
    collection = "'''+collection+'''"
    task = jsonable_encoder(task)
    print("inside create",collection)
    try:
        is_verified = request.state.is_verified       
        is_verified_permissions = json.loads(is_verified['permissions'])
        print("is_verified_permissions",is_verified_permissions)
    except:
        data = {"message":"Unauthorized","result":{}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

    have_permission = False

    # Permissions to check
    permissions_to_check = ["add"]

    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
        
            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(permission in collection_data["permissions"] for permission in permissions_to_check)

                if has_permissions:
                    have_permission = True
            
    if is_verified['user_id']:
        if have_permission:
            created_by = is_verified['user_id']
            task['created_by'] = created_by
            task['modified_by'] = created_by
            if collection != 'leads' or not task.get('assigned_to'):
                task['assigned_to'] = created_by
            else:
                task['assigned_to'] = int(task['assigned_to'])

        else:
            data = {"message":"Forbidden","result":{}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message":"token invalid","result":{}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
    
    today_date = datetime.now().strftime('%Y-%m-%d')
    today_time = datetime.now().strftime('%H-%M-%S')

    # try:        
    if collection == 'projectassignment':
        if await request.app.mongodb[collection].find_one({"user_id": task['user_id'], "project": task["project"]}):
            print("projectassignment record already exists")
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message":"record already exists","result":{}}
            )

    # else:
    
    if collection == 'leads':
        lead_exists = await request.app.mongodb[collection].find_one(
            {"mobile_no": task["mobile_no"], "is_archived": False}
        )
        if lead_exists:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message":"record already exists","result":{}}
            )
    elif collection == 'projects':
        project_exists = await request.app.mongodb[collection].find_one(
            {"name": task.get("name"), "is_archived": False}
        )
        if project_exists:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"message":"record already exists","result":{}}
            )
    
    new_task = await request.app.mongodb[collection].insert_one(task)

    if collection == 'leads':
        try:
            response = requests.post(
                f"{services_server_url}/jobs/schedule",
                headers={'Authorization': request.headers.get('Authorization')},
                json={"lead_id": new_task.inserted_id}
            )
            if response.status_code == 200:
                print("SLA jobs scheduled")
            else:
                print(f"SLA job API failed. Reason {response.text}")
        except Exception as e:
            print(f"Failure while scheduling SLA jobs. Exception: {e}")

    try:
        inserted_id = new_task.inserted_id

        try:
            lead_data = await request.app.mongodb[collection].find_one({"_id": new_task.inserted_id})
            if new_task.inserted_id and lead_data['status']=='New' and lead_data['email'] and lead_data['name'] and lead_data['project_name']:
                send_email_request(
                    lead_id=lead_data['_id'],
                    lead_name=lead_data['name'],
                    lead_email=lead_data['email'],
                    project_name=lead_data['project_name'],
                    web_page=email_web_page_url
                )
        except Exception as e:
            print("error: ", e)

        res = index_in_elastic(task, inserted_id, collection)
        activities_data = {
            "title": "new record added in "+str(collection),
            "type":"Create",
            "user_id": str(created_by),
            "parent_doc_id": str(inserted_id),
            "collection": str(collection),
            "date":today_date,
            "time":today_time,                
            }
        await new_activity(request,activities_data)

        if collection == 'lead_notes':
            lead_id = task['parent_doc_id']
            history_data = {
                "assistant_id": '',
                "conversation_id": '',
                "user_id": str(created_by),
                "lead_id": lead_id,
                "is_ai":False,
                "chat":"Note: "+str(task['note']),
                "agent":"client",
                "created_at": (datetime.now() + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            }
            await request.app.mongodb["chathistory"].insert_one(history_data)

    except:
        pass
    if new_task:
        # Fetch the inserted task from the database using its _id
        new_task = await request.app.mongodb[collection].find_one({"_id": new_task.inserted_id})
        return build_response(status.HTTP_201_CREATED, result=new_task, message="success")
    else:
        return build_response(status.HTTP_204_NO_CONTENT, result={}, message="failed")
    # except Exception as e:
    #     print(str(e))
    #     return build_response(status.HTTP_204_NO_CONTENT, result={}, message="failed")

    # except Exception as e:
    #     print(str(e))
    #     return build_response(status.HTTP_400_BAD_REQUEST, result={}, message=f"failed: {str(e)}")

@router.post("/list", response_description="List all results")
async def list(
    request: Request,
    sort_by: List[str] = Query(["_id"]),
    sort_type: List[int] = Query([1]),
    page: int = 1,
    page_size: int = 1000,
    start_date: str = None,
    end_date: str = None,
    additional_para: str = None,
):
    # try:      
    collection = "'''+collection+'''"
    is_seeder = "'''+str(is_seeder)+'''"
    bizapp=''
    additional_data = "'''+str(additional_data)+'''"
    
    sort_criteria = [item for item in zip(sort_by, sort_type)]
    print(f"{sort_criteria=}")
    token_user_name = ''
    child_ids = []
    # try:
    # Access the 'is_verified' result from the request state
    is_verified = request.state.is_verified
    print("is_verified",is_verified)
    # is_verified = verify_authentication(request)        
    is_verified_permissions = json.loads(is_verified['permissions'])
    bizapp = is_verified['role_bizapp']
    child_ids = is_verified['child_ids']
    token_user_name = is_verified['first_name']
    print("childids",child_ids)
    print("bizapp",bizapp)
    # except:
    #     data = {"message":"Unauthorized","result":{}}
    #     return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

    have_permission = False

    # Permissions to check
    permissions_to_check = ["view"]

    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(permission in collection_data["permissions"] for permission in permissions_to_check)
                if has_permissions:
                    have_permission = True         
            
    if is_verified['user_id']:
        if have_permission:
            modified_by = is_verified['user_id']
            created_by = is_verified['user_id']
        else:
            data = {"message":"Forbidden","result":{}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message":"token invalid","result":{}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)

    created_by_filter = {"created_by": created_by}
    modified_by_filter = {"modified_by": created_by}

    if additional_para is not None and additional_para=='members':
        all_child_ids = []
        for child in child_ids:
            if "children" in child:
                for child_item in child["children"]:
                    all_child_ids.append(child_item["id"])
            all_child_ids.append(child["id"])
    
        # Creating conditions for child IDs
        child_conditions = [{"assigned_to": item} for item in all_child_ids]

        #This is a work around to be updated #TBD    
        if is_seeder == 'False' and bizapp != 'Biz Admin':
            filter_conditions = [{"$or": [*child_conditions]}]
        else:
            filter_conditions = []

    else:
        assigned_to_filter = {"assigned_to": created_by}
        
        if is_seeder == 'False' and bizapp != 'Biz Admin':
            filter_conditions = [{"$or": [assigned_to_filter]}]
        else:
            filter_conditions = []
            
    regex_query = {}
    agent_temp=[]

    try:
        body = await request.body()
        cleaned_json = body.decode('utf-8')
        print(cleaned_json)
        post_data = json.loads(cleaned_json)
        print(post_data)
        # post_data = await request.json()      
    except Exception as e:
        print("post data="+str(e))
        post_data = []


    # if post_data:
    #     temp = [condition for condition in post_data if any(condition[next(iter(condition))]['$in'])]
    #     if start_date is None or start_date == '':
    #         regex_query["$and"] = temp
    #     else:
    #         temp.append({"created_at": { "$gte":start_date+"T00:00:00Z", "$lte":end_date+"T23:59:59Z"}})
    #         regex_query["$and"] = temp
    # else:
    #     if start_date != '' and start_date is not None:
    #         regex_query["$and"] = [{"created_at": { "$gte":start_date+"T00:00:00Z", "$lte":end_date+"T23:59:59Z"}}]

    if post_data:
        #temp = [condition for condition in post_data if any(condition[next(iter(condition))]["$in"])]
        
        temp = []  # Initialize an empty list to store conditions that meet the criteria

        # Iterate over each dictionary (condition) in post_data
        for condition in post_data:
            # Get the first key in the condition dictionary
            first_key = next(iter(condition))
            print("first_key",first_key)
            print(condition[first_key]["$in"])
            if first_key == 'agents':
                print("agent")
                if isinstance(condition[first_key], dict):
                    if len(condition[first_key]["$in"]) > 0:
                
                        # Check if the "$in" key exists in the inner dictionary and if its value is a non-empty list
                        if "$in" in condition[first_key] and condition[first_key]["$in"][0]:
                            # If any of the conditions are true, append this condition to the temp list
                            for agent in condition[first_key]["$in"]:
                                agent_temp.append({"assigned_to":agent})
                print(temp)       
            elif first_key == 'team_leads':
                print("team_leads")
                team_lead_childs=[]
                if len(condition[first_key]["$in"]) > 0:
                    # for team_lead in condition[first_key]["$in"]:
                    try:
                        payload = {"team_leads":condition[first_key]["$in"]}
                        print(payload)
                        sso_response = requests.post(sso_server_url + "/api/team_lead_childs/", data=payload)
                        sso_json = json.loads(sso_response.text)
                        print(sso_json)
                        team_lead_childs = sso_json['result']['childs']
                        team_lead_childs.extend(condition[first_key]["$in"])
                    except:
                        pass
                print("team_lead_childs",team_lead_childs)
                
                try:
                    if len(team_lead_childs)>0:
                        for team_lead_child in team_lead_childs:
                            agent_temp.append({"assigned_to":team_lead_child})
                except:
                    pass
            else:
                # Check if the value corresponding to the first key is a dictionary
                if isinstance(condition[first_key], dict):
                    print("condition[first_key]",condition[first_key])
                    if len(condition[first_key]["$in"]) > 0:
                        # Check if the "$in" key exists in the inner dictionary and if its value is a non-empty list
                        if "$in" in condition[first_key] and condition[first_key]["$in"]:
                            # If any of the conditions are true, append this condition to the temp list
                            temp.append(condition)
                print(temp)
        # temp now contains all the conditions where the first key points to a dictionary containing a non-empty list under the "$in" key

        # print(temp)
        
        if start_date is not None and start_date != '' and end_date is not None and end_date != '':
            # start_date = datetime.strptime(start_date, "%Y-%m-%d")
            # end_date = datetime.strptime(end_date, "%Y-%m-%d")
            temp.append({"created_at":  { "$gte":start_date+" 00:00:00", "$lte":end_date+" 23:59:59"}})
            if additional_para is not None and additional_para == 'priority':
                regex_query["$or"] = temp
            else:
                regex_query["$and"] = temp
        else:
            if additional_para is not None and additional_para == 'priority':
                regex_query["$or"] = temp
            else:
                regex_query["$and"] = temp
        print(regex_query)
        
    else:
        if start_date is not None and start_date != '' and end_date is not None and end_date != '':
            # start_date = datetime.strptime(start_date, "%Y-%m-%d")
            # end_date = datetime.strptime(end_date, "%Y-%m-%d")
            regex_query["$and"] = [{"created_at":  { "$gte":start_date+" 00:00:00", "$lte":end_date+" 23:59:59"}}]

        
    
    # print(regex_query)
    # Merge filter_conditions with regex_query["$and"]
    if filter_conditions:
        regex_query["$and"] = regex_query.get("$and", []) + filter_conditions
        if additional_para is not None and additional_para == 'priority':
            regex_query.get("$and", []).append({'is_archived':{'$in':[False,"false"]}})

    
    print("agent_temp",agent_temp)
    if len(agent_temp)>0:
        agent_case = [{"$or": agent_temp}]
        regex_query["$and"] = regex_query.get("$and", []) + agent_case

    # Don't pass empty array in $and filter
    if "$and" in regex_query:
        if not regex_query["$and"]:
            del regex_query["$and"]
        print(f"regex_query after empty $and check {regex_query}")

    # Get the count first
    count_query = 0
    count_query = await request.app.mongodb[collection].count_documents(regex_query)
    # print("count_query",count_query)
    print("regex_query:", regex_query)
    # print(f"{sort_criteria=}")

    # pipeline = [{"$match": regex_query},{"$group": {"_id": "$status", "count": {"$sum": 1}}}]

    # # Execute aggregation pipeline
    # status_counts = await request.app.mongodb[collection].aggregate(pipeline).to_list(None)
    # print(status_count)
    results = await request.app.mongodb[collection].find(regex_query).sort(sort_criteria).skip((page - 1) * page_size).to_list(length=page_size)
    
    # additional_data_list = {}
    
    if additional_data != "None":
        additional_data = additional_data.split(",")
        
        # Append additional data from other collections
        child_ids_ext = child_ids
        child_ids_ext.append({'name':token_user_name,'id':is_verified['user_id']})
        for task in results: 
            additional_data_list = {}
            assigned_to_id = task['assigned_to']
            
            for child_ext in child_ids_ext:
                if int(assigned_to_id) == int(child_ext['id']) :
                    task['assigned_to_name'] = child_ext['name']

            print("assigned_to_id",assigned_to_id)
            
            for child in child_ids:
            
                try:
                    if int(assigned_to_id) == int(child['id']) :
                        task['is_team_lead'] = False
                    else:
                        task['is_team_lead'] = True
                except:
                    task['is_team_lead'] = False
            
                
                
            for ad in additional_data:
                # Example: Append data from another collection
                try:
                    additional_data_res = await request.app.mongodb[ad].find({"parent_doc_id": task['_id']}).sort([("date", -1)]).to_list(length=4)
                except Exception as e:
                    additional_data_res = await request.app.mongodb[ad].find({"parent_doc_id": task['_id']}).sort([("date", -1)]).to_list(length=4)
                
                        
                # Convert ObjectId to string in the additional_data_res
                for item in additional_data_res:
                    if '_id' in item:
                        item['_id'] = str(item['_id'])

                if additional_data_res:
                    additional_data_list.setdefault(ad, {})
                    additional_data_list[ad]=additional_data_res
                else:
                    additional_data_list.setdefault(ad, [])
            
            # Update the 'additional_data' key in the task with the modified list        
            task['additional_data'] = additional_data_list
            # task['count_query'] = count_query
            # task['status_counts'] = status_counts
    print(f"{results=}")
    return build_response(200, result=results, message="success", count_query=count_query)
    # except Exception as e:
    #     return build_response(status.HTTP_400_BAD_REQUEST, result={}, message=f"failed: {str(e)}")
    
@router.post("/list/{id}", response_description="Get a single result")
async def show(id: str, request: Request):
    # try:
    collection = "'''+collection+'''"
    additional_data = "'''+str(additional_data)+'''"

    try:
        is_verified = request.state.is_verified     
        is_verified_permissions = json.loads(is_verified['permissions'])
    except Exception as e:
        print(e)
        data = {"message":"Unauthorized","result":{}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

    have_permission = False

    # Permissions to check
    permissions_to_check = ["view"]

    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
            
            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(permission in collection_data["permissions"] for permission in permissions_to_check)

                if has_permissions:
                    have_permission = True
                    
            
    if is_verified['user_id']:
        if have_permission:
            modified_by = is_verified['user_id']
            created_by = is_verified['user_id']
        else:
            data = {"message":"Forbidden","result":{}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message":"token invalid","result":{}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
    
    if (
        task := await request.app.mongodb[collection].find_one({"_id": id})
    ) is not None:

        additional_data = additional_data.split(",")

        # Append additional data from other collections     
        additional_data_list = {}
        for ad in additional_data:
            # Example: Append data from another collection
            additional_data_res = await request.app.mongodb[ad].find({"parent_doc_id": task['_id']}).to_list(length=None)
            
            # Convert ObjectId to string in the additional_data_res
            for item in additional_data_res:
                if '_id' in item:
                    item['_id'] = str(item['_id'])
            
            # Add the additional data to the list
            if additional_data_res:
                additional_data_list.setdefault(ad, {})
                additional_data_list[ad]=additional_data_res
            else:
                additional_data_list.setdefault(ad, [])
                
        # Update the 'additional_data' key in the task with the modified list        
        task['additional_data'] = additional_data_list

        return build_response(200, result=task, message="success")
    else:
        return build_response(status.HTTP_404_NOT_FOUND, result={}, message="not found")
    # except Exception as e:
    #     return build_response(status.HTTP_400_BAD_REQUEST, result={}, message=f"failed: {str(e)}")

@router.post("/delete/{id}", response_description="Delete a record")
async def show(id: str, request: Request):
    collection = "'''+collection+'''"
    business_code = "'''+str(business_code)+'''"

    try:
        is_verified = request.state.is_verified
        is_verified_permissions = json.loads(is_verified['permissions'])
    except Exception as e:
        print(e)
        data = {"message": "Unauthorized", "result": {}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

    have_permission = False

    # Permissions to check
    permissions_to_check = ["edit"]

    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():

            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(
                    permission in collection_data["permissions"] for permission in permissions_to_check)

                if has_permissions:
                    have_permission = True

    if not have_permission:
        data = {"message": "Forbidden", "result": {}}
        return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)

    if not is_verified['user_id']:
        data = {"message": "token invalid", "result": {}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)

    if (await request.app.mongodb[collection].find_one({"_id": id})) is not None:
        delete_result = await request.app.mongodb[collection].delete_one({"_id": id})

        if delete_result.deleted_count == 1:
            try:
                collection_index = business_code + "." + collection.lower()
                es.delete(index=collection_index, id=id)
                return build_response(200, result={}, message="success")
            except Exception as e:
                print(f"FAILED TO DELETE FROM ELASTICSEARCH collection={collection} - id={id}")
                print(e)
            return build_response(200, result={}, message="success")
        else:
            return build_response(500, result={}, message="failed")

    else:
        return build_response(status.HTTP_404_NOT_FOUND, result={}, message="not found")

@router.post("/search", response_description="List all results")
async def search(
    request: Request,
    sort_by: List[str] = Query(["_id"]),
    sort_type: List[int] = Query([1]),
    page: int = 1,
    page_size: int = 1000,
):
    # try:      
    collection = "'''+collection+'''"
    is_seeder = "'''+str(is_seeder)+'''"
    additional_data = "'''+str(additional_data)+'''"
    sort_criteria = [item for item in zip(sort_by, sort_type)]
    print(f"{sort_criteria=}")
    biz_app=''
    try:
        is_verified = request.state.is_verified     
        is_verified_permissions = json.loads(is_verified['permissions'])
        bizapp = is_verified['role_bizapp']
        child_ids = is_verified['child_ids']
        token_user_name = is_verified['first_name']

        print(child_ids)
    except Exception as e:
        print(e)
        data = {"message":"Unauthorized","result":{}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

    have_permission = False

    # Permissions to check
    permissions_to_check = ["view"]

    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
        
            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(permission in collection_data["permissions"] for permission in permissions_to_check)

                if has_permissions:
                    have_permission = True
            
    if is_verified['user_id']:
        if have_permission:
            modified_by = is_verified['user_id']
            created_by = is_verified['user_id']
        else:
            data = {"message":"Forbidden","result":{}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message":"token invalid","result":{}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)

    created_by_filter = {"created_by": created_by}
    assigned_to_filter = {"assigned_to": created_by}
    modified_by_filter = {"modified_by": created_by}

    try:
        # Creating conditions for child IDs
        child_conditions = [{"assigned_to": child["id"]} for child in child_ids]
        print(child_conditions)
    except:
        child_conditions=[]
    print(child_conditions)
    if is_seeder == 'False' and bizapp != 'Biz Admin':
        filter_conditions = [{"$or": [assigned_to_filter, *child_conditions]}]
    else:
        filter_conditions = []

    # filter_conditions = [{"$or": [assigned_to_filter]}]
    regex_query = {}

    try:
        body = await request.body()
        post_data = json.loads(body)
        # post_data = await request.json()           
    except  Exception as e:
        print(e)
        post_data = {}

    if post_data:
        query = post_data['query']
        # Create a query that searches on multiple fields using regex
        if query:
            fields_to_search = post_data['fields_to_search']
            regex_query["$or"] = [{field: {"$regex": query, "$options": "i"}} for field in fields_to_search]

    # Merge filter_conditions with regex_query["$and"]
    if filter_conditions:
        regex_query["$and"] = regex_query.get("$and", []) + filter_conditions

    print(f"{regex_query=}")
    print(f"{sort_criteria=}")
    results = await request.app.mongodb[collection].find(regex_query).sort(sort_criteria).skip((page - 1) * page_size).to_list(length=page_size)

    additional_data = additional_data.split(",")
    
    child_ids_ext = child_ids
    child_ids_ext.append({'name':token_user_name,'id':is_verified['user_id']})
    # Append additional data from other collections
    for task in results:      

        assigned_to_id = task['assigned_to']
        
        for child_ext in child_ids_ext:
            if int(assigned_to_id) == int(child_ext['id']) :
                task['assigned_to_name'] = child_ext['name']
        
        for child in child_ids:
            try:
                if int(assigned_to_id) == int(child['id']) :
                    task['is_team_lead'] = False
                else:
                    task['is_team_lead'] = True
            except:
                task['is_team_lead'] = False

        additional_data_list = {}
        for ad in additional_data:
            # Example: Append data from another collection
            additional_data_res = await request.app.mongodb[ad].find({"parent_doc_id": task['_id']}).to_list(length=None)
            
            # Convert ObjectId to string in the additional_data_res
            for item in additional_data_res:
                if '_id' in item:
                    item['_id'] = str(item['_id'])
            
            # Add the additional data to the list
            if additional_data_res:
                additional_data_list.setdefault(ad, {})
                additional_data_list[ad]=additional_data_res
            else:
                additional_data_list.setdefault(ad, [])
            
        # Update the 'additional_data' key in the task with the modified list        
        task['additional_data'] = additional_data_list

    return build_response(200, result=results, message="success")
    # except Exception as e:
    #     return build_response(status.HTTP_400_BAD_REQUEST, result={}, message=f"failed: {str(e)}")
    
@router.post("/update/{id}", response_description="Update a record")
async def update_task(id: str, request: Request, task: '''+collection+'''UpdateModel = Body(...)):
    
    # try:
    collection = "'''+collection+'''"
    additional_data = "'''+str(additional_data)+'''"
    business_code =  "'''+str(business_code)+'''"

    task = jsonable_encoder(task)

    try:
        is_verified = request.state.is_verified       
        is_verified_permissions = json.loads(is_verified['permissions'])
    except Exception as e:
        print(e)
        data = {"message":"Unauthorized","result":{}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)

    have_permission = False

    # Permissions to check
    permissions_to_check = ["edit"]

    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
        
            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(permission in collection_data["permissions"] for permission in permissions_to_check)

                if has_permissions:
                    have_permission = True
            
    if is_verified['user_id']:
        if have_permission:
            modified_by = is_verified['user_id']
            created_by = is_verified['user_id']
            task['modified_by'] = modified_by
        else:
            data = {"message":"Forbidden","result":{}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message":"token invalid","result":{}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)

    filter_conditions = {"_id": id}
    
    # Allow to update "assigned_to" if collection is "leads"
    if collection == 'leads' and task.get('assigned_to'):
        task['assigned_to'] = int(task['assigned_to'])
        
    if collection == 'leads':
        skip_fields = ("created_by", "created_at")
    else:
        skip_fields = ("created_by", "created_at", "assigned_to")

    # Extract fields that should be updated, excluding certain fields
    update_fields = {key: value for key, value in task.items() if key not in skip_fields}

    # Update the document in MongoDB
    update_result = await request.app.mongodb[collection].update_one(filter_conditions, {"$set": update_fields})

    today_date = datetime.now().strftime('%Y-%m-%d')
    today_time = datetime.now().strftime('%H-%M-%S')

    # Check if the update in MongoDB was successful
    if update_result.modified_count > 0:
        try:
            resp = es.update(index=business_code+"." + collection.lower(), id=id, doc=task)
            activities_data = {
                "title": "Record updated in "+str(collection),
                "type":"Update",
                "user_id": str(created_by),
                "parent_doc_id": str(id),
                "collection": str(collection),
                "date":today_date,
                "time":today_time,
                }
            await new_activity(request,activities_data)
        except  Exception as e:
            print(e)
            pass

    new_task = await request.app.mongodb[collection].find_one({"_id": id})

    additional_data = additional_data.split(",")

    # Append additional data from other collections     
    additional_data_list = {}
    for ad in additional_data:
        # Example: Append data from another collection
        additional_data_res = await request.app.mongodb[ad].find({"parent_doc_id": new_task['_id']}).to_list(length=None)
        # Convert ObjectId to string in the additional_data_res
        for item in additional_data_res:
            if '_id' in item:
                item['_id'] = str(item['_id'])
        # Add the additional data to the list
        if additional_data_res:
            additional_data_list.setdefault(ad, {})
            additional_data_list[ad]=additional_data_res
        else:
            additional_data_list.setdefault(ad, [])
            
    # Update the 'additional_data' key in the task with the modified list        
    new_task['additional_data'] = additional_data_list

    return build_response(status.HTTP_201_CREATED, result=new_task, message="success")
    # except Exception as e:
    #     return build_response(status.HTTP_400_BAD_REQUEST, result={}, message=f"failed: {str(e)}")

''')

    if collection == 'newleads':
        with open(routers_file_path, 'a') as f2:
            f2.write('''
from .models import ''' + collection + '''CombinedModel

@router.post("/lead_create", response_description="Add new lead and enquiry info")
async def lead_create(request: Request, combined: ''' + collection + '''CombinedModel = Body(...)):
    collection = "'''+collection+'''"
    lead_data = jsonable_encoder(combined.lead)
    enquiry_info_data = jsonable_encoder(combined.enquiry_info)
    lead_data.pop("_id", None)
    enquiry_info_data.pop("_id", None)
    print("inside create",collection)
    try:
        is_verified = request.state.is_verified       
        is_verified_permissions = json.loads(is_verified['permissions'])
        print("is_verified_permissions",is_verified_permissions)
    except:
        data = {"message":"Unauthorized","result":{}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)
    
    have_permission = False
    
    # Permissions to check
    permissions_to_check = ["add"]
    
    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
        
            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(permission in collection_data["permissions"] for permission in permissions_to_check)
    
                if has_permissions:
                    have_permission = True
            
    if is_verified['user_id']:
        if have_permission:
            created_by = is_verified['user_id']
            lead_data.update({
                "created_by": created_by,
                "modified_by": created_by,
                "assigned_to": created_by
            })
            enquiry_info_data.update({
                "created_by": created_by,
                "modified_by": created_by,
                "assigned_to": created_by
            })
        else:
            data = {"message":"Forbidden","result":{}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message":"token invalid","result":{}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
    
    existing_lead = await request.app.mongodb[collection].find_one({"mobile_no": lead_data["mobile_no"]})
    
    lead_project_name_empty = not (lead_data.get('project_name') and lead_data['project_name'].strip())
    
    existing_lead_project_name_empty = not (
                existing_lead.get('project_name') and existing_lead['project_name'].strip()) if existing_lead else False
                
    if lead_project_name_empty and existing_lead and existing_lead_project_name_empty:
        lead_id = existing_lead["_id"]
        latest_enquiry = await request.app.mongodb["leadenquiry"].find_one(
            {"lead_id": lead_id},
            sort=[("created_at", -1)]
        )
        if latest_enquiry:
            last_enquiry_date_str = latest_enquiry["created_at"]
            last_enquiry_date = datetime.strptime(last_enquiry_date_str, '%Y-%m-%d %H:%M:%S')
            enquiry_info_data["lead_id"] = lead_id
            if (datetime.now() - last_enquiry_date).days < 30:
                update_result = await request.app.mongodb["leadenquiry"].update_many(
                    {"_id": latest_enquiry["_id"]},
                    {"$set": enquiry_info_data}
                )
                if update_result.modified_count > 0:
                    lead_result = await request.app.mongodb[collection].find_one({"_id": lead_id})
                    enquiry_info_result = await request.app.mongodb["leadenquiry"].find_one(
                        {"_id": latest_enquiry["_id"]})
                    combined_data = {
                        "lead": lead_result,
                        "enquiry_info": enquiry_info_result
                    }
                    return JSONResponse(status_code=status.HTTP_200_OK,
                                        content={"result": combined_data, "message": "success"})
                else:
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                                        detail="Failed to update enquiry")
            else:
                enquiry_info_data["lead_id"] = lead_id
    else:
        lead_id = str(uuid.uuid4())
        enquiry_info_id = str(uuid.uuid4())
        lead_data["_id"] = lead_id
        enquiry_info_data["_id"] = enquiry_info_id
        enquiry_info_data["lead_id"] = lead_id
        today_date = datetime.now().strftime('%Y-%m-%d')
        today_time = datetime.now().strftime('%H-%M-%S')

    lead_result = await request.app.mongodb[collection].insert_one(lead_data)
    enquiry_info_result = await request.app.mongodb["leadenquiry"].insert_one(enquiry_info_data)
    
    # try:
    #     response = requests.post(
    #         f"{services_server_url}/jobs/schedule",
    #         headers={'Authorization': request.headers.get('Authorization')},
    #         json={"lead_id": lead_result.inserted_id}
    #     )
    #     if response.status_code == 200:
    #         print("SLA jobs scheduled")
    #     else:
    #         print(f"SLA job API failed. Reason {response.text}")
    # except Exception as e:
    #     print(f"Failure while scheduling SLA jobs. Exception: {e}")
    try:
        inserted_id = lead_result.inserted_id
        try:
            lead_data = await request.app.mongodb[collection].find_one({"_id": lead_result.inserted_id})
            if lead_result.inserted_id and lead_data['status']=='New' and lead_data['email'] and lead_data['name'] and enquiry_info_data['projects']:
                send_email_request(
                    lead_id=lead_data['_id'],
                    lead_name=lead_data['name'],
                    lead_email=lead_data['email'],
                    project_name=enquiry_info_data['projects'],
                    web_page=email_web_page_url
                )
        except Exception as e:
            print("error: ", e)
    
        res = index_in_elastic(lead_data, inserted_id, collection)
        activities_data = {
            "title": "new record added in "+str(collection),
            "type":"Create",
            "user_id": str(created_by),
            "parent_doc_id": str(inserted_id),
            "collection": str(collection),
            "date":today_date,
            "time":today_time,                
            }
        await new_activity(request,activities_data)
    except:
        pass
    if lead_result:
        # Fetch the inserted task from the database using its _id
        lead_result = await request.app.mongodb[collection].find_one({"_id": lead_result.inserted_id})
        enquiry_info_result = await request.app.mongodb["leadenquiry"].find_one({"_id": enquiry_info_result.inserted_id})
        combined_data = {
            "lead": lead_result,
            "enquiry_info": enquiry_info_result
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content={"result": combined_data, "message": "success"})
    else:
        return build_response(status.HTTP_204_NO_CONTENT, result={}, message="failed")

@router.get("/lead_info/{lead_id}", response_description="Get lead and enquiry info by lead_id")
async def get_lead_info(request: Request, lead_id: str):
    lead_collection = "'''+collection+'''"
    enquiry_collection = "leadenquiry"
    try:
        is_verified = request.state.is_verified
        is_verified_permissions = json.loads(is_verified['permissions'])
        print("is_verified_permissions", is_verified_permissions)
    except Exception as e:
        print(f"Verification error: {e}")
        data = {"message": "Unauthorized", "result": {}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)
    
    have_permission = False

    # Permissions to check
    permissions_to_check = ["view"]
    
    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
            if collection_data["collection_name"] == lead_collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(
                    permission in collection_data["permissions"] for permission in permissions_to_check)
                if has_permissions:
                    have_permission = True
                    print("Permission granted")
    
    print(f"have_permission: {have_permission}")
    if is_verified['user_id']:
        if not have_permission:
            data = {"message": "Forbidden", "result": {}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message": "token invalid", "result": {}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
    
    try:
        print(f"Fetching lead data for lead_id: {lead_id}")
        lead_data = await request.app.mongodb[lead_collection].find_one({"_id": lead_id})
        if not lead_data:
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"message": "Lead not found"})

        print(f"Fetching enquiry data for lead_id: {lead_id}")
        enquiry_info_data = await request.app.mongodb[enquiry_collection].find({"lead_id": lead_id}).to_list(None)

        combined_data = {
            "lead": lead_data,
            "enquiry_info": enquiry_info_data
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content={"result": combined_data, "message": "success"})
    except Exception as e:
        print(f"Unexpected error: {e}")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            content={"message": "Internal Server Error"})
                            
@router.put("/lead_update/{lead_id}", response_description="Partially update lead and enquiry info")
async def lead_update(request: Request, lead_id: str, task: ''' + collection + '''CombinedModel = Body(...)):
    collection = "'''+collection+'''"
    enquiry_collection = "leadenquiry"
    business_code = 'ee'
    lead_data = jsonable_encoder(task.lead)
    enquiry_info_data = jsonable_encoder(task.enquiry_info)
    # Remove _id if it exists to avoid trying to update it
    lead_data.pop("_id", None)
    enquiry_info_data.pop("_id", None)
    
    try:
        is_verified = request.state.is_verified
        is_verified_permissions = json.loads(is_verified['permissions'])
        print("is_verified_permissions", is_verified_permissions)
    except:
        data = {"message": "Unauthorized", "result": {}}
        return JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content=data)
    
    have_permission = False

    # Permissions to check
    permissions_to_check = ["edit"]

    # Loop through the data structure
    for entry in is_verified_permissions:
        for collection_id, collection_data in entry.items():
            if collection_data["collection_name"] == collection:
                # Check if any of the required permissions exist in the collection's permissions
                has_permissions = any(
                    permission in collection_data["permissions"] for permission in permissions_to_check)
                if has_permissions:
                    have_permission = True
                    print("Permission granted")
    
    print(f"have_permission: {have_permission}")
    if is_verified['user_id']:
        if have_permission:
            modified_by = is_verified['user_id']
            created_by = is_verified['user_id']
        else:
            data = {"message": "Forbidden", "result": {}}
            return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=data)
    else:
        data = {"message": "token invalid", "result": {}}
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=data)
    
    today_date = datetime.now().strftime('%Y-%m-%d')
    today_time = datetime.now().strftime('%H-%M-%S')
    
    try:
        if lead_data:
            update_result = await request.app.mongodb[collection].update_one(
                {"_id": lead_id}, {"$set": lead_data}
            )
            if update_result.modified_count == 0:
                return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"message": "Lead not found"})
            else:
                try:
                    resp = es.update(index=business_code + "." + collection.lower(), id=lead_id, doc=lead_data)
                    activities_data = {
                        "title": "Record updated in " + str(collection),
                        "type": "Update",
                        "user_id": str(created_by),
                        "parent_doc_id": str(id),
                        "collection": str(collection),
                        "date": today_date,
                        "time": today_time,
                    }
                    await new_activity(request, activities_data)
                except  Exception as e:
                    print(e)
                    pass
        if enquiry_info_data:
            enquiry_update_result = await request.app.mongodb[enquiry_collection].update_many(
                {"lead_id": lead_id}, {"$set": enquiry_info_data}
            )
            if enquiry_update_result.modified_count == 0:
                return JSONResponse(status_code=status.HTTP_404_NOT_FOUND,
                                    content={"message": "Enquiry info not found"})
        
        # Fetch updated lead data
        lead_result = await request.app.mongodb[collection].find_one({"_id": lead_id})

        # Fetch updated enquiry info data
        enquiry_info_result = await request.app.mongodb[enquiry_collection].find({"lead_id": lead_id}).to_list(None)

        combined_data = {
            "lead": lead_result,
            "enquiry_info": enquiry_info_result
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content={"result": combined_data, "message": "success"})
    except Exception as e:
        print(f"Unexpected error: {e}")
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            content={"message": "Internal Server Error"})
''')

    with open(main_file_path, 'a') as f3:
        router_import_line = f"\nfrom apps.{business_code}.{collection}.routers import router as {business_code}_{collection}_router\n"
        router_include_line = f'app.include_router({business_code}_{collection}_router, tags=["{collection}"], prefix="/{collection}")'

        # Read the current content of the file
        with open(main_file_path, 'r') as f:
            content = f.read()

        # Check if the lines are already present
        if router_import_line not in content and router_include_line not in content:
            with open(main_file_path, 'a') as f:
                f.write(router_import_line)
                f.write(router_include_line)
                f.close()
        # f3.write("\nfrom apps."+str(business_code)+"."+collection+".routers import router as "+str(business_code)+"_"+collection+"_router\n")
        # f3.write('app.include_router('+str(business_code)+"_"+collection+'_router, tags=["'+collection+'"], prefix="/'+collection+'")')
        # f3.close()

    commit_msg = str(business_code)+'_'+str(collection)

    # try:

    # Add changes
    repo.git.add('--all')
    repo.index.commit(commit_msg)



    # Merge changes from the remote branch into your local branch
    current_branch = repo.active_branch
    origin_branch_name = f'origin/{current_branch.name}'

    if repo.index.unmerged_blobs():
        # Handle merge conflicts
        print("Merge conflicts detected. Please resolve conflicts.")
    else:
        try:
            repo.git.merge(origin_branch_name)
            repo.index.commit("Merge changes from remote branch")
        except:
            pass
    # Merge changes from the remote branch into your local branch
    # current_branch = repo.active_branch
    # origin_branch_name = f'origin/{current_branch.name}'
    # repo.git.merge(origin_branch_name)
    # Pull changes from the remote repository (assuming you are on the main branch)

    if settings.CD_DYNAMIC_SERVICES_BRANCH == 'pr' or settings.CD_DYNAMIC_SERVICES_BRANCH == 'release':
        #TBD
        # if last_tag is None:
        #     current_version = "0.0.0.0"
        #     part_to_increase = 2  # Specify the part to increase (index starts from 0)


        last_tag = repo.git.describe('--tags', repo.git.rev_list('--tags', '--max-count=1'))

        print("last_tag",last_tag)


        part_to_increase = 3
        new_tag = increase_version(last_tag, part_to_increase)
        print("new_tag",new_tag)

        # Add a tag
        tag = repo.create_tag(new_tag, message=f"Tagging version {new_tag}")


    # Push local changes to the remote repository
    origin.push()

    # except Exception as e:
    #     print('Bad request occurred: {}'.format(e))
    #     return Response({'result': 'Bad request occurred: {}'.format(e), 'status_code':400}, status=status.HTTP_400_BAD_REQUEST)

    return JsonResponse({"message": "success"}, status=200)


class CollectionView(APIView):

    # def dispatch(self, *args, **kwargs):
    #     # Apply caching only for GET requests
    #     if self.request.method.lower() == 'get':
    #         self.dispatch = method_decorator(cache_page(60 * 15, cache='default'))(super().dispatch)
    #     return super().dispatch(*args, **kwargs)

    def get(self, request, pk=None, format=None):
        try:
            is_verified = verify_authentication(request)
            user_id = is_verified['user_id']
            user_org = is_verified["business"]["organization"]["name"]
        except Exception as e:
            print(e)
            data = {"message":"Unauthorized","result":{}}
            return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)

        # try:
        name = request.GET.get('name')
        group = request.GET.get('group','')
        org = request.GET.get('org','')

        business_code = request.GET.get('business_code','')

        if org:
            if org != user_org:
                data = {"message":"Unauthorized","result":{}}
                return Response({'result':data},status=status.HTTP_403_FORBIDDEN)
            business_codes = Business.objects.filter(organization__name__iexact=org).values_list('business_code', flat=True).iterator()

            # Create a Q object to combine multiple queries
            q_objects = Q(business_code__iexact='')
            for code in business_codes:
                q_objects |= Q(business_code__iexact=code)

            # Combine the Q object with the name filter
            collection = Collection.objects.filter(q_objects).order_by('name').iterator()


            # collection = Collection.objects.filter(business_code__iexact__in=business_code_list)
        else:
            if name and business_code:
                collection = Collection.objects.filter(business_code__iexact=business_code).filter(name__iexact=name).order_by('name').iterator()
            else:
                collection = Collection.objects.filter(business_code__iexact=business_code).order_by('name').iterator()

        serializer = CollectionSerializer(collection, many=True)

        if group:
            groups = {}
            for p in serializer.data:
                if p['group'] not in groups:
                    groups[p['group']] = [p]
                else:
                    groups[p['group']].append(p)
            return Response({'result':groups},status=status.HTTP_200_OK)
        else:
            for x in serializer.data:
                action_fields = []

                x['create_end_point']= dynamic_fast_api_server+'/'+str(name)+'/create'
                x['list_end_point']= dynamic_fast_api_server+'/'+str(name)+'/list'
                x['update_end_point']= dynamic_fast_api_server+'/'+str(name)+'/update'

                collection_id = x['id']
                collection_fields = CollectionFields.objects.prefetch_related('seeder').filter(collection_id=collection_id).order_by('sequence').iterator()
                field_serializer = CollectionFieldsSerializer(collection_fields, many=True)
                field_list = []
                # x['collection_fields']=field_serializer.data
                for field in field_serializer.data:
                    if field['seeder'] is not None:
                        collection_fields_ext = CollectionFields.objects.prefetch_related('seeder').filter(collection_id=field['seeder']['collection']['id']).order_by('sequence').iterator()
                        field_serializer_ext = CollectionFieldsSerializer(collection_fields_ext, many=True)
                        field['seeder']['collection_fields'] = field_serializer_ext.data
                        field['seeder']['create_end_point']= dynamic_fast_api_server+'/'+str(field['seeder']['collection']['name'])+'/create'
                        field['seeder']['list_end_point']= dynamic_fast_api_server+'/'+str(field['seeder']['collection']['name'])+'/list'
                        field['seeder']['update_end_point']= dynamic_fast_api_server+'/'+str(field['seeder']['collection']['name'])+'/update'

                    field_list.append(field)

                x['collection_fields'] = field_list

                if x['action_fields'] is not None:
                    for xy in (x['action_fields']).split(","):

                        collection_a = Collection.objects.filter(business_code__iexact=business_code).filter(name__iexact=xy).iterator()
                        serializer_action = CollectionSerializer(collection_a, many=True)

                        for field_a in serializer_action.data:

                            field_a['create_end_point']= dynamic_fast_api_server+'/'+str(xy)+'/create'
                            field_a['list_end_point']= dynamic_fast_api_server+'/'+str(xy)+'/list'
                            field_a['update_end_point']= dynamic_fast_api_server+'/'+str(xy)+'/update'

                            field_a['collection_fields'] = field_list

                            collection_fields_action = CollectionFields.objects.prefetch_related('seeder').filter(collection__name__iexact=xy).order_by('sequence').iterator()
                            field_serializer_action = CollectionFieldsSerializer(collection_fields_action, many=True)

                            # field_list_action = []

                            # for field in field_serializer.data:
                            #     field_list_action.append(field)

                            temp = {
                                "field":xy,
                                "display_name":field_a['display_name'],
                                "list_end_point":dynamic_fast_api_server+'/'+xy+'/list',
                                "create_end_point":dynamic_fast_api_server+'/'+xy+'/create',
                                "update_end_point":dynamic_fast_api_server+'/'+xy+'/update',
                                "fields":{
                                    "id":123,
                                    "collection": serializer_action.data[0],
                                    "list_end_point":dynamic_fast_api_server+'/'+xy+'/list',
                                    "create_end_point":dynamic_fast_api_server+'/'+xy+'/create',
                                    "update_end_point":dynamic_fast_api_server+'/'+xy+'/update',
                                    "collection_fields":field_serializer_action.data
                                }
                            }

                            action_fields.append(temp)

                    x['action_fields'] = action_fields

                # for xy in field_list:
                #     if xy['seeder'] is not None:
                #         temp = {
                #             "field":xy['name'],
                #             "list_end_point":fast_api_server+'/'+xy['seeder']['collection']['name']+'/list',
                #             "create_end_point":fast_api_server+'/'+xy['seeder']['collection']['name']+'/create',
                #             "update_end_point":fast_api_server+'/'+xy['seeder']['collection']['name']+'/update',
                #             "fields":xy['seeder']
                #         }
                #         action_fields.append(temp)
                # x['action_fields'] = action_fields

            return Response({'result':serializer.data},status=status.HTTP_200_OK)

        # except Exception as e:
        #         return Response({'result': 'Bad request occurred: {}'.format(e), 'status_code':400}, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    def post(self, request, format=None):
        # try:
        try:
            is_verified = verify_authentication(request)
            user_id = is_verified['user_id']
        except Exception as e:
            print(e)
            data = {"message":"Unauthorized","result":{}}
            return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)


        type = request.POST.getlist('type')
        fname = request.POST.getlist('fname')
        group = request.POST.getlist('group')
        is_seeder = request.POST.getlist('is_seeder')
        seeder = request.POST.getlist('seeder')
        required = request.POST.getlist('required')
        # validation_type = request.POST.getlist('validation_type')
        sequence = request.POST.getlist('sequence')
        unique = request.POST.getlist('unique')
        display = request.POST.getlist('display')
        field_display_name = request.POST.getlist('field_display_name')
        field_desc = request.POST.getlist('field_desc')

        print(field_display_name)
        print(field_desc)
        # Create a dictionary to store the labels and names
        data = {}
        j=1

        # Iterate over the provided data to construct the JSON structure
        for idx, (name, label, display) in enumerate(zip(fname, field_display_name, display), start=1):
            if display:
                data[str(j)] = {'label': label, 'name': name}
                j=j+1
        # Convert the dictionary to JSON
        # json_data = json.dumps(data, indent=4)

        # Now json_data contains the JSON structure similar to the one mentioned above

        serializer = CollectionSerializer(data=request.data)

        if serializer.is_valid():
            serializer.validated_data['display_fields'] = data
            serializer.save()
            i=0
            for rd in fname:
                try:
                    fname_s = fname[i]
                except:
                    fname_s = ''
                try:
                    type_s = type[i]
                except:
                    type_s= ''
                try:
                    seeder_s = seeder[i]
                    x = Seeder.objects.filter(collection__id=seeder_s).first()
                    seeder_s = x.id
                except:
                    seeder_s = None
                try:
                    if sequence[i]:
                        sequence_s = sequence[i]
                    else:
                        sequence_s = 1.0000
                except:
                    sequence_s = 1.0000
                try:
                    if unique[i] == 'true':
                        unique_s = True
                    else:
                        unique_s = False

                except:
                    unique_s = False

                try:
                    if display[i] == 'true':
                        display_s = True
                    else:
                        display_s = False

                except:
                    display_s = False

                # try:
                #     validation_type_s = validation_type[i]
                # except:
                #     validation_type_s = ''
                try:
                    if required[i] == 'true':
                        required_s = True
                    else:
                        required_s = False
                except:
                    required_s = False

                CollectionFields.objects.create(collection_id=serializer.data['id'],unique=unique_s, required=required_s, name=fname_s,type=type_s,seeder_id=seeder_s,sequence=sequence_s,display=display_s, display_name=field_display_name[i],field_desc=field_desc[i])
                i = i+1
            service_generator(request, serializer.data['name'], serializer.data['business_code'])
            return  Response({'result':serializer.data}, status=status.HTTP_201_CREATED)
        else:
            emessage=serializer.errors
            return Response({'msg': emessage},status=status.HTTP_400_BAD_REQUEST)
        # except Exception as e:
        #     print(e)
        #     return Response({'msg': 'Please retry!'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @transaction.atomic
    def put(self, request, pk, format=None):
        # try:

        try:
            is_verified = verify_authentication(request)
            user_id = is_verified['user_id']
        except Exception as e:
            data = {"message":"Unauthorized","result":{}}
            return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)

        master = Collection.objects.get(id=pk)
        serializer = CollectionSerializer(instance=master, data=request.data)

        type = request.POST.getlist('type')
        fname = request.POST.getlist('fname')
        group = request.POST.getlist('group')
        is_seeder = request.POST.getlist('is_seeder')
        seeder = request.POST.getlist('seeder')
        required = request.POST.getlist('required')
        validation_type = request.POST.getlist('validation_type')
        sequence = request.POST.getlist('sequence')
        unique = request.POST.getlist('unique')
        display = request.POST.getlist('display')
        field_display_name = request.POST.getlist('field_display_name')
        field_desc = request.POST.getlist('field_desc')

        # Create a dictionary to store the labels and names
        data = {}

        # Iterate over the provided data to construct the JSON structure
        j=1
        for idx, (name, label, display_f) in enumerate(zip(fname, field_display_name, display), start=1):
            print("display",display)
            if display_f == 'true':
                print("here")
                data[str(j)] = {'label': label, 'name': name}
                j=j+1

        # Convert the dictionary to JSON
        # json_data = json.dumps(data, indent=4)


        if serializer.is_valid():
            serializer.validated_data['display_fields'] = data
            serializer.save()
            CollectionFields.objects.filter(collection_id=pk).delete()
            i=0
            for rd in fname:
                try:
                    fname_s = fname[i]
                except:
                    fname_s = ''
                try:
                    type_s = type[i]
                except:
                    type_s= ''
                try:
                    seeder_s = seeder[i]
                    x = Seeder.objects.filter(collection__id=seeder_s).first()
                    seeder_s = x.id
                except:
                    seeder_s = None
                try:
                    if sequence[i]:
                        sequence_s = sequence[i]
                    else:
                        sequence_s = 1.0000
                except:
                    sequence_s = 1.0000
                try:
                    if unique[i] == 'true':
                        unique_s = True
                    else:
                        unique_s = False

                except:
                    unique_s = False
                # try:
                #     validation_type_s = validation_type[i]
                # except:
                #     validation_type_s = ''
                print("display[i]",display[i])
                try:
                    if display[i] == 'true':
                        display_s = True
                    else:
                        display_s = False
                except:
                    display_s = False

                try:
                    if required[i] == 'true':
                        required_s = True
                    else:
                        required_s = False
                except:
                    required_s = False

                CollectionFields.objects.create(collection_id=pk,unique=unique_s, required=required_s, name=fname_s,type=type_s,seeder_id=seeder_s,sequence=sequence_s,display=display_s, display_name=field_display_name[i],field_desc=field_desc[i])
                i = i+1
            service_generator(request, serializer.data['name'], serializer.data['business_code'])
            return Response({'result':serializer.data},status=status.HTTP_200_OK)
        else:
            emessage=serializer.errors
            return Response({'message': emessage},status=status.HTTP_400_BAD_REQUEST)
        # except Exception:
        #     return Response({'msg': 'Please retry!'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SampleExportView(APIView):

    def get(self, request, pk=None, format=None):
        try:
            try:
                is_verified = verify_authentication(request)
                user_id = is_verified['user_id']
            except:
                data = {"message":"Unauthorized","result":{}}
                return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)

            collection = request.GET.get('collection')
            collection_fields = CollectionFields.objects.filter(collection__name__iexact=collection).order_by('sequence')
            # fields = CollectionFields._meta.get_fields()
            serializer = CollectionFieldsSerializer(collection_fields, many=True)
            fields_list=[]
            for fields in serializer.data:
                fields_list.append(fields['name'])
            unique_fields_list = list(set(fields_list))
            return Response({'result':unique_fields_list},status=status.HTTP_200_OK)
        except Exception as e:
                return Response({'result': 'Bad request occurred: {}'.format(e), 'status_code':400}, status=status.HTTP_400_BAD_REQUEST)

class BusinessView(APIView):

    def get(self, request, pk=None, format=None):
        try:
            try:
                is_verified = verify_authentication(request)
                user_id = is_verified['user_id']
                business_code = is_verified["business"]["business_code"]
            except Exception as e:
                print(e)
                data = {"message":"Unauthorized","result":{}}
                return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)

            name = request.query_params.get('name', None)
            org = request.query_params.get('org', None)
            if org:
                business = Business.objects.filter(organization__name__iexact=org).order_by('name')
            else:
                # Check if the 'name' parameter is provided
                if name:
                    # Filter businesses by name
                    business = Business.objects.filter(name__iexact=name).order_by('name')
                else:
                    # No 'name' parameter provided, fetch all businesses linked to business code
                    business = Business.objects.filter(business_code=business_code).order_by('name')

            serializer = BusinessSerializer(business, many=True)
            return Response({'result':serializer.data},status=status.HTTP_200_OK)
        except Exception as e:
                return Response({'result': 'Bad request occurred: {}'.format(e), 'status_code':400}, status=status.HTTP_400_BAD_REQUEST)

    @transaction.atomic
    def post(self, request, format=None):
        # try:
        try:
            is_verified = verify_authentication(request)
            user_id = is_verified['user_id']
        except Exception as e:
            print(e)
            data = {"message":"Unauthorized","result":{}}
            return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)

        serializer = BusinessSerializer(data=request.data)
        if serializer.is_valid():
            organization_id = request.data.get('organization', None)
            if organization_id:
                organization = Organization.objects.get(pk=organization_id)
                serializer.validated_data['organization'] = organization
            serializer.save()
            return  Response({'result':serializer.data}, status=status.HTTP_201_CREATED)
        else:
            emessage=serializer.errors
            return Response({'msg': emessage},status=status.HTTP_400_BAD_REQUEST)
        # except Exception as e:
        #     return Response({'msg': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @transaction.atomic
    def put(self, request, pk, format=None):
        try:
            try:
                is_verified = verify_authentication(request)
                user_id = is_verified['user_id']
            except Exception as e:
                print(e)
                data = {"message":"Unauthorized","result":{}}
                return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)
            master = Business.objects.get(id=pk)
            serializer = BusinessSerializer(instance=master, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response({'result':serializer.data},status=status.HTTP_200_OK)
            else:
                emessage=serializer.errors
                return Response({'message': emessage},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response({'msg': 'Please retry!'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OrganizationView(APIView):

    def get(self, request, pk=None, format=None):
        try:
            # try:
            #     is_verified = verify_authentication(request)
            #     user_id = is_verified['user_id']
            # except Exception as e:
            #     print(e)
            #     data = {"message":"Unauthorized","result":{}}
            #     return Response({'result':data},status=status.HTTP_401_UNAUTHORIZED)

            organization = Organization.objects.all().order_by('name')
            serializer = OrganizationSerializer(organization, many=True)
            return Response({'result':serializer.data},status=status.HTTP_200_OK)
        except Exception as e:
                return Response({'result': 'Bad request occurred: {}'.format(e), 'status_code':400}, status=status.HTTP_400_BAD_REQUEST)

class BizAppView(APIView):

    def get(self, request, pk=None, format=None):
        try:
            organization = BizApp.objects.all().order_by('name')
            serializer = BizAppSerializer(organization, many=True)
            return Response({'result':serializer.data},status=status.HTTP_200_OK)
        except Exception as e:
                return Response({'result': 'Bad request occurred: {}'.format(e), 'status_code':400}, status=status.HTTP_400_BAD_REQUEST)
