from ftplib import error_perm
from django.shortcuts import render
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status, viewsets
from salesforce import settings
import requests
import json
import os
from .query import *
import urllib
from urllib.parse import urlparse
from urllib.parse import parse_qs
from . models import UserModel,SalseforceTable,SalseforceTableFields,SalseforceTableField
from urllib.parse import urlparse
from django.db.models import Q
# https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_user_agent_flow.htm&type=5


def generat_refresh_token(request):
    try:
        session_data = request.session.get('user')

        if "refresh_token" in session_data:

            params = {
                "Authorization": "Basic",
                "grant_type": "refresh_token",
                "client_id": settings.SALESFORCE_CONSUMER_KEY,
                "client_secret": settings.SALESFORCE_CONSUMER_SECRET,
                "refresh_token": session_data['refresh_token']
            }

            del session_data['refresh_token']

            r = requests.post(
                "https://login.salesforce.com/services/oauth2/token", params=params)

            if r.status_code == 200:
                credentials = r.json()
                user = {"access_token": credentials["access_token"], "refresh_token": credentials["refresh_token"], "domain": credentials[
                    "instance_url"], "id": credentials["id"], "issued_at": credentials["issued_at"], "signature": credentials["signature"]}
                request.session['user'] = user
                return credentials

        else:
            credentials = {"message": "refresh token not available"}
            return credentials

    except Exception as ex:
        return ex


class GeneratRefreshToken(viewsets.ViewSet):
    def create(self, request):
        try:
            if request.data.get('refresh_token') != "" and request.data.get('refresh_token') != None:
                refresh_token = request.data.get("refresh_token")
            else:
                json_response = {
                    "status": 400, "message": "Please enter the valide refresh_token"}
                return Response(json_response)

            params = {
                "Authorization": "Basic",
                "grant_type": "refresh_token",
                "client_id": settings.SALESFORCE_CONSUMER_KEY,
                "client_secret": settings.SALESFORCE_CONSUMER_SECRET,
                "refresh_token": refresh_token
            }

            r = requests.post(
                "https://login.salesforce.com/services/oauth2/token", params=params)

            if r.status_code == 200:
                credentials = r.json()
                json_response = {"credentials": credentials,
                                 "status": 200, "message": "Success"}
                return Response(json_response)
            else:
                error = r.json()
                json_response = {"message": error, "status": 400}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)


class LoginViewSet(viewsets.ViewSet):
    def create(self, request):
        try:
            if request.data.get('url') != "" and request.data.get('url') != None:
                url = request.data.get("url")
            else:
                json_response = {"status": 400,
                                 "message": "Please enter the valide code"}
                return Response(json_response)

            decoded_url = urllib.parse.unquote(url)
            parsed_url = urlparse(decoded_url)
            code = parse_qs(parsed_url.query)['code'][0]

            redirect_url = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_url)
            
            # code = urllib.parse.unquote(code)

            params = {
                "grant_type": "authorization_code",
                "client_id": settings.SALESFORCE_CONSUMER_KEY,
                "client_secret": settings.SALESFORCE_CONSUMER_SECRET,
                "redirect_uri":"",
                "code": code
            }
            r = requests.post(
                "https://login.salesforce.com/services/oauth2/token", params=params)

            credentials = r.json()

            if r.status_code == 200:

                user_vo = UserModel()

                user_exists = UserModel.objects.filter(
                    userName=credentials["instance_url"])

                if len(user_exists) == 0:
                    user_vo.userName = credentials["instance_url"]
                    user_vo.save()
                    
                    user_f_key = UserModel.objects.get(userName=credentials["instance_url"])
                    
                    tables = ["Opportunity","Lead","Contact","Events","Account"]
                
                    fields = {
                              "Opportunity" : ["Id","AccountId","Name","Description","Amount","NextStep","Probability","LeadSource","Type","CloseDate"],
                              "Lead":["Id","Name","FirstName","LastName","LastName","Email","Company","Title"],
                              "Contact":["Id","Name","LastName","FirstName","Email","AccountId"],
                              "Events":["Id","Subject"],
                              "Account":["Id","Name","Industry","Phone"]
                              }
                    
            
                    for table,fields in fields.items() :  
                        salseforcetablefields_vo = SalseforceTableFields()
                        table_f_key = SalseforceTable.objects.get(tableName = table,userID__userName= credentials["instance_url"] )
                        salseforcetablefields_vo.tableID = table_f_key
                        salseforcetablefields_vo.fieldsName = json.dumps(fields)
                        salseforcetablefields_vo.save()
                    
                    table_name = "Opportunity"

                else:
                    user = UserModel.objects.get(userName=credentials["instance_url"])
                    table_name = user.tableName
            
                json_response = {"status": 200, "credentials": credentials, "message": "Success"}
                return Response(json_response)

            else:
                json_response = {
                    "message": credentials["error_description"], "status": 400}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)




class TableFieldsType(viewsets.ViewSet):

     def create(self, request):
        try:
            if request.data.get("table_name") != "" and request.data.get("table_name") != None:
                table_name = request.data.get("table_name")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide table_name"}
                return Response(json_response)

            if request.data.get("access_token") != "" and request.data.get("access_token") != None:
                access_token = request.data.get("access_token")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide access_token"}
                return Response(json_response)

            if request.data.get("host") != "" and request.data.get("host") != None:
                host = request.data.get("host")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide host"}
                return Response(json_response)
            
            validate = is_access_token_validate(host, access_token)

            if validate == "True":
                fields_records = field_type(table_name, host,access_token)

                json_response = {"headers": fields_records, "status": 200, "message": "Success"}
                return Response(json_response)

            else:
                json_response = {
                    "message": "Your Access token was expired", "status": 401}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)
        
        

class TableRecord(viewsets.ViewSet):
    def create(self, request):
        try:
            if request.data.get("table_name") != "" and request.data.get("table_name") != None:
                table_name = request.data.get("table_name")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide table_name"}
                return Response(json_response)

            if request.data.get("limit") != "" and request.data.get("limit") != None:
                limit = request.data.get("limit")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide limit"}
                return Response(json_response)

            if request.data.get("offset") != "" and request.data.get("offset") != None:
                offset = request.data.get("offset")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide offset"}
                return Response(json_response)

            if request.data.get("access_token") != "" and request.data.get("access_token") != None:
                access_token = request.data.get("access_token")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide access_token"}
                return Response(json_response)

            if request.data.get("host") != "" and request.data.get("host") != None:
                host = request.data.get("host")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide host"}
                return Response(json_response)

            if request.data.get("fields") != "" and request.data.get("fields") != None:
                fields = request.data.get("fields")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide fields"}
                return Response(json_response)

            validate = is_access_token_validate(host, access_token)

            if validate == "True":
                table_record = table_data(table_name, limit, offset, access_token, host,fields)
                if table_record["status"] != 400:
                    json_response = {
                        "rows": table_record['rows'],"headers": table_record['headers'], "status": 200, "message": "Success"}
                    return Response(json_response)
                else:
                    json_response = {"status": 400, "message":table_record["error"]}
                    return Response(json_response)
                
            else:    
                json_response = {
                    "message": "Your Access token was expired", "status": 401}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)
        

class CreateRecord(viewsets.ViewSet):
    def create(self, request):
        try:
            if request.data.get("access_token") != "" and request.data.get("access_token") != None:
                access_token = request.data.get("access_token")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide access_token"}
                return Response(json_response)

            if request.data.get("host") != "" and request.data.get("host") != None:
                host = request.data.get("host")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide host"}
                return Response(json_response)

            if request.data.get("table_name") != "" and request.data.get("table_name") != None:
                table_name = request.data.get("table_name")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide table_name"}
                return Response(json_response)

            if request.data.get("fields") != "" and request.data.get("fields") != None:
                fields = request.data.get("fields")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide fields"}
                return Response(json_response)

            fields_json = json.dumps(fields)
            validate = is_access_token_validate(host, access_token)

            if validate == "True":
                r = requests.post(f"{host}/services/v53.0/sobjects/{table_name}/", data=fields_json, headers={
                                  "Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})

                message = r.json()

                if r.status_code == 201:
                    json_response = {
                        "message": f"Record Create Successfully And Newrecord id  = {message['id']}", "status": 200, }
                    return Response(json_response)
                else:
                    json_response = {
                        "message": f"Data Not Update Successfully Because {message[0]['message']}", "status": 400}
                    return Response(json_response)
            else:
                json_response = {
                    "message": "Your Access token was expired", "status": 401}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)


class UpdateRecord(viewsets.ViewSet):
    def create(self, request):

        try:
            if request.data.get("access_token") != "" and request.data.get("access_token") != None:
                access_token = request.data.get("access_token")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide access_token"}
                return Response(json_response)

            if request.data.get("host") != "" and request.data.get("host") != None:
                host = request.data.get("host")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide host"}
                return Response(json_response)

            if request.data.get("table_name") != "" and request.data.get("table_name") != None:
                table_name = request.data.get("table_name")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide table_name"}
                return Response(json_response)

            if request.data.get("field") != "" and request.data.get("field") != None:
                fields = request.data.get("field")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide fields"}
                return Response(json_response)

            if request.data.get("id") != "" and request.data.get("id") != None:
                id = request.data.get("id")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide id"}
                return Response(json_response)

            # fields = json.loads(json.dumps(fields))
            validate = is_access_token_validate(host, access_token)

            if validate == "True":
                fields_json = json.dumps(fields)
                r = requests.patch(f"{host}/services/data/v53.0/{table_name}/{id}", data=fields_json, headers={
                                   "Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})

                status_code = r.status_code

                if status_code == 204:
                    json_response = {
                        "message": "Record Update Successfully", "status": 200}
                    return Response(json_response)

                else:
                    message = r.json()
                    json_response = {
                        "message": f"Data not update successfully because {message[0]['errorCode']}", "status": 400}
                    return Response(json_response)

            else:
                json_response = {
                    "message": "Your Access token was expired", "status": 401}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)


class DeleteRecord(viewsets.ViewSet):
    def create(self, request):
        try:
            if request.data.get("access_token") != "" and request.data.get("access_token") != None:
                access_token = request.data.get("access_token")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide access_token"}
                return Response(json_response)

            if request.data.get("host") != "" and request.data.get("host") != None:
                host = request.data.get("host")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide host"}
                return Response(json_response)

            if request.data.get("table_name") != "" and request.data.get("table_name") != None:
                table_name = request.data.get("table_name")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide table_name"}
                return Response(json_response)

            if request.data.get("id") != "" and request.data.get("id") != None:
                id = request.data.get("id")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide id"}
                return Response(json_response)

            validate = is_access_token_validate(host, access_token)

            if validate == "True":
                r = requests.delete(f"{host}/services/data/v53.0/sobjects/{table_name}/{id}",
                                    headers={"Authorization": f"Bearer {access_token}"})
                status_code = r.status_code

                if status_code == 204:
                    json_response = {
                        "message": "Record Delete Successfully", "status": 200}
                    return Response(json_response)

                else:
                    message = r.json()
                    json_response = {
                        "message": f"Data not Delete successfully because id {message[0]['errorCode']}", "status": 400}
                    return Response(json_response)

            else:
                json_response = {
                    "message": "Your Access token was expired", "status": 401}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)


class GetSalseforceAllTable(viewsets.ViewSet):

    def create(self,request):
        
        host = request.data.get("host")
        access_token = request.data.get("access_token")

        validate = is_access_token_validate(host, access_token)

        sobject = []
        if validate == "True":
            r = requests.get(f"{host}/services/data/v55.0/sobjects/",
                             headers={"Authorization": f"Bearer {access_token}"})

            if r.status_code == 200:
                sobjects = r.json()

                for i in sobjects["sobjects"]:
                    sobject.append(
                        {"sobject": i["name"], "sobject lable": i["lable"]})

        else:
            json_response = {
                "message": "Your Access token was expired", "status": 401}
            return Response(json_response)



class UpdateFields(viewsets.ViewSet):

    def create(self, request):
        
        try:
            if request.data.get("access_token") != "" and request.data.get("access_token") != None:
                access_token = request.data.get("access_token")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide access_token"}
                return Response(json_response)

            if request.data.get("host") != "" and request.data.get("host") != None:
                host = request.data.get("host")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide host"}
                return Response(json_response)
            
            if request.data.get("sobject") != "" and request.data.get("sobject") != None:
                sobject = request.data.get("sobject")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide sobject"}
                return Response(json_response)
            
            field = request.data.get("field")
            
            validate = is_access_token_validate(host, access_token)


            if validate == "True":
                if "." in field:
                    
                    split_fields  = field.split(".")
                    chek_record = SalseforceTableField.object.filter(tableName = sobject,userID__userName = "",fieldName = split_fields[1],parentSobject = split_fields[0] )
                    if len(chek_record) == 1:
                        json_response = {
                            "message": "already fields in database", "status": 401}
                        return Response(json_response)
                    else:
                        table = split_fields[0]
                        query = requests.get(f"{host}/services/data/v53.0/sobjects/{table}/describe",headers={"Authorization": f"Bearer {access_token}"})
                        
                        q_result = query.json()
                        table_f_key = SalseforceTable.objects.get(tableName = sobject,userID__userName = "" )
                        
                        for i in q_result['fields']:
                            if i["name"]  == split_fields[1]:
                                salseforcetablefield_vo = SalseforceTableField()
                                salseforcetablefield_vo.tableID = table_f_key
                                salseforcetablefield_vo.fieldName = i["name"]
                                salseforcetablefield_vo.fieldDisplayName = i["label"]
                                salseforcetablefield_vo.fieldDataType = i["type"]
                                salseforcetablefield_vo.fieldPicklistValue = json.dumps([j['label'] for j in i["picklistValues"]]) if i["type"] == "picklist" else []
                                salseforcetablefield_vo.fieldEditable = i["updateable"]
                                salseforcetablefield_vo.parentSobject = split_fields[1]
                                # salseforcetablefield_vo.save()
                                break
                        
                else:
                    chek_record = SalseforceTableField.object.filter(tableName = sobject,userID__userName = "",fieldName = field)

                    if len(chek_record) == 1:
                        json_response = {
                            "message": "already fields in database", "status": 401}
                        return Response(json_response)

                    else:
                        query = requests.get(f"{host}/services/data/v53.0/sobjects/{table}/describe",headers={"Authorization": f"Bearer {access_token}"})
                        q_result = query.json()
                        table_f_key = SalseforceTable.objects.get(tableName = sobject,userID__userName = "" )
                        for i in q_result['fields']:
                             
                            if i["name"]  == split_fields[1]:
                                salseforcetablefield_vo = SalseforceTableField()
                                salseforcetablefield_vo.tableID = table_f_key
                                salseforcetablefield_vo.fieldName = i["name"]
                                salseforcetablefield_vo.fieldDisplayName = i["label"]
                                salseforcetablefield_vo.fieldDataType = i["type"]
                                salseforcetablefield_vo.fieldPicklistValue = json.dumps([j['label'] for j in i["picklistValues"]]) if i["type"] == "picklist" else []
                                salseforcetablefield_vo.fieldEditable = i["updateable"]
                                # salseforcetablefield_vo.save()
                                break
                    
            else:
                json_response = {
                    "message": "Your Access token was expired", "status": 401}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)


        
class TableRecord(viewsets.ViewSet):
    def create(self, request):
        try:
            if request.data.get("table_name") != "" and request.data.get("table_name") != None:
                table_name = request.data.get("table_name")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide table_name"}
                return Response(json_response)

            if request.data.get("limit") != "" and request.data.get("limit") != None:
                limit = request.data.get("limit")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide limit"}
                return Response(json_response)

            if request.data.get("offset") != "" and request.data.get("offset") != None:
                offset = request.data.get("offset")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide offset"}
                return Response(json_response)

            if request.data.get("access_token") != "" and request.data.get("access_token") != None:
                access_token = request.data.get("access_token")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide access_token"}
                return Response(json_response)

            if request.data.get("host") != "" and request.data.get("host") != None:
                host = request.data.get("host")
            else:
                json_response = {"status": 400,
                                 "message": "Please Enter Valide host"}
                return Response(json_response)

            validate = is_access_token_validate(host, access_token)

            if validate == "True":
                table_record = table_data_with_parent(table_name, limit, offset, access_token, host)
                if table_record["status"] != 400:
                    json_response = {
                        "rows": table_record['rows'],"headers": table_record['headers'], "status": 200, "message": "Success"}
                    return Response(json_response)
                else:
                    json_response = {"status": 400, "message":table_record["error"]}
                    return Response(json_response)
                
            else:    
                json_response = {
                    "message": "Your Access token was expired", "status": 401}
                return Response(json_response)

        except Exception as ex:
            json_response = {"message": ex, "status": 400}
            return Response(json_response)



































