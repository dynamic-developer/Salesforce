from django.db import models

class UserModel(models.Model):
    userID= models.AutoField(db_column="userID", primary_key=True, null=False)
    userName = models.TextField(db_column="userName", max_length=255, default="", null=False)
    tableName = models.TextField(db_column="tableName", max_length=255, default="Opportunity", null=False)
    
    def __str__(self):
        return '{} {}'.format(self.userID, self.userName,self.tableName)

    def __as_dict__(self):
        return {
            "userID": self.userID,
            "userName":self.userName,
            "tableName":self.tableName
        }
        
    class Meta:
        db_table = "user_table"
        
        
class SalseforceTable(models.Model):
    tableID = models.AutoField(db_column="tableID", primary_key=True, null=False)
    userID = models.ForeignKey(UserModel, on_delete=models.CASCADE,
                                                db_column="userID")
    tableName = models.TextField(db_column="tableName", max_length=255, default="", null=False)

    def __str__(self):
        return '{} {} {}'.format(self.tableID, self.userID,self.tableName)

    def __as_dict__(self):
        return {
            "tableID": self.tableID,
            "userID":self.userID,
            "tableName":self.tableName,
        }

    class Meta:
        db_table = "salseforcetable_table"
        
        
class SalseforceTableFields(models.Model):
    fieldsID = models.AutoField(db_column="fieldsID", primary_key=True, null=False)
    tableID = models.ForeignKey(SalseforceTable, on_delete=models.CASCADE,
                                                db_column="tableID")
    fieldsName = models.TextField(db_column="fieldsName",  max_length=2550000000000000,default="", null=False)

    def __str__(self):
        return '{} {} {}'.format(self.fieldsID, self.tableID,self.fieldsName)

    def __as_dict__(self):
        return {
            "fieldsID": self.fieldsID,
            "tableID":self.tableID,
            "fieldsName":self.fieldsName
        }

    class Meta:
        db_table = "salseforce_table_fields_table"     
        
 
class SalseforceTableField(models.Model):
    fieldsID = models.AutoField(db_column="fieldsID", primary_key=True, null=False)
    tableID = models.ForeignKey(SalseforceTable, on_delete=models.CASCADE,
                                                db_column="tableID")
    parentSobject = models.TextField(db_column="parentSobject",  max_length=255,default="", null=True)
    fieldName = models.TextField(db_column="fieldName",  max_length=255,default="", null=False)
    fieldDisplayName =  models.TextField(db_column="fieldDisplayName",  max_length=255,default="", null=False)
    fieldDataType = models.TextField(db_column="fieldDataType",  max_length=255,default="", null=False)
    fieldPicklistValue = models.TextField(db_column="fieldPicklistValue",  max_length=255555555555555,default="", null=True)
    fieldEditable = models.BooleanField(db_column="fieldEditable")


    def __str__(self):
        return '{} {} {} {} {} {} {} {}'.format(self.fieldsID, self.tableID,self.parentSobject,self.fieldName,self.fieldDisplayName,self.fieldDataType,self.fieldPicklistValue,self.fieldEditable)

    def __as_dict__(self):
        return {
            "fieldsID": self.fieldsID,
            "tableID":self.tableID,
            "parentSobject":self.parentSobject,
             "fieldName":self.fieldName,
             "fieldDisplayName":self.fieldDisplayName,
             "fieldDataType":self.fieldDataType,
             "fieldPicklistValue":self.fieldPicklistValue,
             "fieldEditable":self.fieldEditable,
             
        }

    class Meta:
        db_table = "salseforce_table_field_table"     
        