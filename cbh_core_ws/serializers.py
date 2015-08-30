# -*- coding: utf-8 -*-

import codecs
import csv
import cStringIO

from django.conf import settings
from django.http import Http404, HttpResponse
from django.template import Context
from django.template.loader import get_template
from django.utils import timezone
from tastypie.serializers import Serializer

import re
import json
import xlsxwriter
import os
import xlrd
import pandas as pd
import numpy as np


import pybel

import copy

def get_field_name_from_key(key):
    return key.replace(u"__space__", u" ")

def get_key_from_field_name(name):
    return name.replace(u" ", u"__space__")






class CustomFieldXLSSerializer(Serializer):
    ''' COde for preparing an Excel summary of the custom fields for the given project '''
    formats = ['json', 'jsonp', 'xls']
    content_types = {'json': 'application/json',
                     'jsonp': 'text/javascript', 
                     'xls': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
    
    def to_xls(self, data, options=None):
        
        output = cStringIO.StringIO()
        exp_json = data.get('custom_field_config')

        cleaned_data = []
        
        #need to manipulate the dataset which is used to apply to dataframe
        #date fields do not have allowed values but do have specified data ranges
        for field in exp_json:
            
            #is it a date field? add the date ranges to the allowed values column
            if(field['field_type'] == 'date'):
                field['field_type'] = 'Date'
                field['allowed_values'] = 'Valid Date'
            elif(field['field_type'] == 'uiselecttags'):
                field['field_type'] = 'Multiple select'
                field['placeholder'] = 'Select one or more of the Allowed Values, separated by a comma'
            elif(field['field_type'] == 'percentage'):
                field['field_type'] = 'Percentage'
                field['allowed_values'] = '0-100%'
            elif(field['field_type'] == 'text'):
                field['field_type'] = 'Plain Text'
                field['allowed_values'] = 'Plain Text. There may be a character length restriction on this field.'



        df = pd.DataFrame(exp_json, columns=['title', 'field_type', 'placeholder', 'allowed_values'])
        #human readable titles
        df.rename(columns={'title': 'Name', 'field_type': 'Data Type', 'placeholder': 'Description', 'allowed_values': 'Allowed Values'}, inplace=True)

        #deal with empty fields
        df.fillna('', inplace=True)

        #autosize column widths setup
        widths = []
        for col in df.columns.tolist():
            col = str(col)
            titlewidth = len(col)
            try:
                w = df[col].astype(unicode).str.len().max()
                if w > titlewidth:
                    widths.append(int(w*1.2))
                else:
                    widths.append(int(titlewidth* 1.2))
            except:
                widths.append(int(titlewidth* 1.2))

        writer = pd.ExcelWriter('temp.xlsx', engine='xlsxwriter')
        writer.book.filename = output
        df.to_excel(writer, sheet_name='Sheet1', index=False)
        workbook = writer.book
        format = workbook.add_format()
        worksheet = writer.sheets['Sheet1']
        format.set_text_wrap()
        #make the UOx ID and SMILES columns bigger
        #BUG - can't set column format until pandas 0.16
        #https://github.com/pydata/pandas/issues/9167
        for index, width in enumerate(widths):
            if width > 150:
                width = 150
            elif width < 15:
                width = 15
            worksheet.set_column(index ,index , width)
        writer.save()
        
        return output.getvalue()



class CustomFieldsSerializer(CustomFieldXLSSerializer):
    pass