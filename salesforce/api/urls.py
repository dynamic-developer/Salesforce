from django.urls import path,include
from .views import LoginViewSet,TableRecord,DeleteRecord,UpdateRecord,CreateRecord,GeneratRefreshToken,TableRecord,GetSalseforceAllTable,UpdateFields,TableFieldsType,test
from rest_framework import routers
from rest_framework.routers import DefaultRouter
router = DefaultRouter()

router.register('login', LoginViewSet,basename="login")
router.register('test', test,basename="test")

router.register('get_tabledata', TableRecord,basename="get_tabledata")
router.register('create_record',CreateRecord,basename="create_record")
router.register('update_record',UpdateRecord,basename="update_record")
router.register('delete_record',DeleteRecord,basename="delete_record")
router.register('refresh_token',GeneratRefreshToken,basename="refresh_token")
router.register('table_records',TableRecord,basename="table_records")
router.register('get_all_table',GetSalseforceAllTable,basename="get_all_table")
router.register('update_fields',UpdateFields,basename="update_fields")
router.register('get_table_fields',TableFieldsType,basename="get_table_fields")


urlpatterns = [
  path('', include(router.urls)),
]


















