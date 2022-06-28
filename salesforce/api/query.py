from cProfile import label
from attr import field
import requests
from django.shortcuts import render
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status, viewsets
import requests
import json
from . models import UserModel,SalseforceTable,SalseforceTableFields,SalseforceTableField

def is_access_token_validate(host,token):
    
    params = {
        "token":token,
        "client_id":"",
        "client_secret":"",
        "token_type_hint":"access_token"
        }
    query = requests.post(f"{host}/services/oauth2/introspect",params = params)
    data = query.json()
    
    false = "false"
    if "active" in data.keys():
        if str(data['active']) == "True":
            return str(data['active'])
        else:
            return false       
    else:
        return false



def field_type(tablename,host,accesstoken):
    
    fields_name = SalseforceTableFields.objects.filter(tableID__tableName = "Opportunity",tableID__userID__userName = "" )
    jsonDec = json.decoder.JSONDecoder()
    fieldlist = jsonDec.decode(fields_name[0].fieldsName)
    fields = ','.join(fieldlist)
    
    query = requests.get(f"{host}/services/data/v53.0/sobjects/{tablename}/describe",headers={"Authorization": f"Bearer {accesstoken}"})
    
    q_result = query.json()
    # table_fields = {}
    table_fields = []
    
    for i in q_result['fields']:
        
        if i["name"] in fieldlist:
            table_fields.append({"sobject":tablename,"metric_name":i['name'],"metric_display_name":i['label'],"metric_datatype":i['type'],"values": [j['label'] for j in i["picklistValues"] ]if i["type"] == "picklist" else [],"editable":i['updateable']})

    parent_table_list = {}
    parent_table_fields = []
    for z in fieldlist:
        if "." in z:
            split_fields  = z.split(".")
            if split_fields[0] in parent_table_list.keys():
                parent_table_list[split_fields[0]].append(split_fields[1])
            else:
                parent_table_list.update({split_fields[0]:[split_fields[1]]})

    for a,b in parent_table_list.items():
        
        p_query = requests.get(f"{host}/services/data/v53.0/sobjects/{a}/describe",headers={"Authorization": f"Bearer {accesstoken}"})
        p_result = p_query.json()
        
        for p in p_result["fields"]:
            if p["name"] in b :
                table_fields.append({"parent_sobject":a,"metric_name":f"{a}.{p['name']}","metric_display_name":p['label'],"metric_datatype":p['type'],"values": [j['label'] for j in p["picklistValues"] ]if p["type"] == "picklist" else [],"editable":p['updateable']})
               
        print(table_fields)
        
    return table_fields


def table_data(tablename,limit,offset,accesstoken,host):

    fields_name = SalseforceTableFields.objects.filter(tableID__tableName = "Opportunity",tableID__userID__userName = "" )
    jsonDec = json.decoder.JSONDecoder()
    fieldlist = jsonDec.decode(fields_name[0].fieldsName)
    fields = ','.join(fieldlist)

    query = requests.get(f"{host}/services/data/v53.0/query/?q=SELECT {fields} FROM {tablename} ORDER BY {tablename}.name LIMIT {limit} OFFSET {offset}",headers={"Authorization": f"Bearer {accesstoken}"})
    table_data = query.json()

    table_fields = field_type(tablename,host,accesstoken)
    header = [i for i in table_fields if i["metric_name"] in fieldlist ]
    
    json_response = {"rows":table_data['records'],"headers":header}
    return json_response



def table_data_allfields(tablename,limit,offset,accesstoken,host): 

    fields_name = SalseforceTableFields.objects.filter(tableID__tableName = "Opportunity",tableID__userID__userName = "")
    jsonDec = json.decoder.JSONDecoder()
    fieldlist = jsonDec.decode(fields_name[0].fieldsName)
    fields = ','.join(fieldlist)
    
    query = requests.get(f"{host}/services/data/v53.0/query/?q=SELECT {fields} FROM {tablename} ORDER BY {tablename}.name LIMIT {limit} OFFSET {offset}",headers={"Authorization": f"Bearer {accesstoken}"})
    table_records= query.json()
    

    query = requests.get(f"{host}/services/data/v53.0/sobjects/{tablename}/describe",headers={"Authorization": f"Bearer {accesstoken}"})
    table_fields_data = query.json()
    parent_fields = [i for i in table_fields_data['fields'] if len(i["referenceTo"]) != 0 ]
   
    
    final_parent_fields = [i for i in parent_fields if i["name"] in fieldlist]
    
    for i in table_records['records']:
        for j in final_parent_fields:
            lenth = len(j["referenceTo"])
            if lenth == 0:
                continue
                    
            primary_table = j["referenceTo"][0]
            foreign_key_id = j["name"]
            if i[foreign_key_id] != None :
                query = requests.get(f"{host}/services/data/v53.0/query/?q=SELECT FIELDS(ALL) from {primary_table} WHERE Id='{i[foreign_key_id]}'",headers={"Authorization": f"Bearer {accesstoken}"})
                query_data = query.json()
                i[j["name"]]={primary_table:query_data['records'][0]}
                
            else :
                pass  
     
    table_fields = field_type(tablename,host,accesstoken)
    header = [i for i in table_fields if i["metric_name"] in fieldlist ]
    json_response = {"rows":table_records['records'],"headers":header}

    return json_response


def table_data_with_parent(tablename,limit,offset,accesstoken,host):

    query = requests.get(f"{host}/services/data/v53.0/sobjects/{tablename}/describe",headers={"Authorization": f"Bearer {accesstoken}"})
    table_fields_data = query.json()
    parent_fields = [i for i in table_fields_data['fields'] if len(i["referenceTo"]) != 0 ]
    
    query = requests.get(f"{host}/services/data/v53.0/query/?q=SELECT FIELDS(ALL) FROM {tablename}  LIMIT {limit} OFFSET {offset}",headers={"Authorization": f"Bearer {accesstoken}"})
    table_records= query.json()
    
    for i in table_records['records']:
        for j in parent_fields:
            lenth = len(j["referenceTo"])
            if lenth == 0:
                continue
            for k,v in i.items():
                if k == j["name"] and lenth != 0:
                    primary_table = j["referenceTo"][0]
                    foreign_key_id = j["name"]
                    if v != None :
                        query = requests.get(f"{host}/services/data/v53.0/query/?q=SELECT FIELDS(ALL) from {primary_table} WHERE Id='{i[foreign_key_id]}'",headers={"Authorization": f"Bearer {accesstoken}"})
                        query_data = query.json()
                        i[k]={primary_table:query_data['records'][0]}
                        break
     
    table_fields = []
    
    for i in table_fields_data['fields']:
        table_fields.append({"sobject":tablename,"metric_name":i['name'],"metric_display_name":i['label'],"metric_datatype":i['type'],"values": [j['label'] for j in i["picklistValues"] ]if i["type"] == "picklist" else [],"editable":i['updateable']})

    json_response = {"rows":table_records['records'],"headers":table_fields}

    return json_response


  