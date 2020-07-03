# -*- coding: utf-8 -*-
from __future__ import unicode_literals

__version__ = '0.0.1'

import frappe
from frappe import msgprint
from frappe.utils import nowdate
from frappe import utils
import json, requests, time
from frappe.utils.password import get_decrypted_password, set_encrypted_password
from six import string_types
from frappe.utils import cstr, unique, cint
import re


UNTRANSLATED_DOCTYPES = ["DocType", "Role"]

def pmaker_getAuth():
	
	pmakerUser = frappe.get_doc("PMaker User", frappe.session.user)
	pmakerUser.pm_password = get_decrypted_password("PMaker User", frappe.session.user, "pm_password", False)
	pmaker = frappe.get_doc('PMaker')        
	headers = {'content-type':'application/json'}

	if pmakerUser.token_expire_in == 0 or pmakerUser.new_token_request:
		payload = {
			"grant_type": "password",
			"scope": pmakerUser.scope,
			"client_id": pmaker.client_id,
			"client_secret": pmaker.client_secret,
			"username": pmakerUser.pm_username,
			"password": pmakerUser.pm_password}

		# Request for bearer token
		token_response = requests.post( pmaker.base_url + pmaker.token_url, data=json.dumps(payload), headers=headers, verify=False)

		# Parse bearer token json
		bearer_token = token_response.json()
		print("========================= new Token  ======================")
		print(bearer_token)
		pmakerUser.access_token = bearer_token['access_token']
		pmakerUser.refresh_token = bearer_token['refresh_token']
		pmakerUser.token_expire_in = int(bearer_token['expires_in'])
		pmakerUser.token_type = bearer_token['token_type']
		pmakerUser.token_expiry =  time.time() + bearer_token['expires_in']
		pmakerUser.new_token_request = False
		pmakerUser.save()
		return 	"Bearer " + pmakerUser.access_token
	elif time.time() > float(pmakerUser.token_expiry)-60:
		payload = {
			"grant_type": "refresh_token",
			"client_id": pmaker.client_id,
			"client_secret": pmaker.client_secret,
			"refresh_token": pmakerUser.refresh_token}
		# Request for bearer token
		token_response = requests.post( pmaker.base_url + pmaker.token_url, data=json.dumps(payload), headers=headers, verify=False)

		# Parse bearer token json
		bearer_token = token_response.json()
		print("========================= Bearer Token  ======================")
		print(bearer_token)
		pmakerUser.access_token = bearer_token['access_token']
		pmakerUser.refresh_token = bearer_token['refresh_token']
		pmakerUser.token_expire_in = int(bearer_token['expires_in'])
		pmakerUser.token_type = bearer_token['token_type']
		pmakerUser.token_expiry =  time.time() + bearer_token['expires_in']
		pmakerUser.save()
		return 	"Bearer " + bearer_token['access_token']
	else:
		return 	"Bearer " + pmakerUser.access_token



@frappe.whitelist(allow_guest=True)
def getLogintest():
	return {'usr':"perkasajob@gmail.com", 'pwd': "ssdd"}

@frappe.whitelist()
def getTestSaveDoctype():
	pmaker = frappe.get_doc('PMaker')
	pmaker.token_type = "Bearer"
	pmaker.save()
	return pmaker


@frappe.whitelist()
def getLoginPM():
	return frappe.db.get_value("User",{"name":frappe.session.user}, "pm_username")
	username = frappe.db.get_value("User",{"name":frappe.session.user}, "username")
	return  frappe.get_doc("PMaker User", username).as_dict()

@frappe.whitelist()
def getPMakerAuthToken():
	return pmaker_getAuth()

@frappe.whitelist()
def getPMakerUser():
	pmaker = frappe.get_doc('PMaker')
	headers = {'content-type':'application/json', 'Authorization' : pmaker_getAuth()}    
	token_response = requests.get( pmaker.base_url  + '/api/1.0/workflow/users', headers=headers, verify=False)
	# Parse response json
	res = token_response.json()
			
	return res

@frappe.whitelist()
def getPMakerCases():
	pmaker = frappe.get_doc('PMaker')
	headers = {'content-type':'application/json', 'Authorization' : pmaker_getAuth()}    
	token_response = requests.get( pmaker.base_url  + '/api/1.0/workflow/cases', headers=headers, verify=False)
	# Parse response json
	res = token_response.json()
			
	return res

@frappe.whitelist()
def getPMakerCasesPage():
	pmaker = frappe.get_doc('PMaker')
	headers = {'content-type':'application/json', 'Authorization' : pmaker_getAuth()}    
	token_response = requests.get( pmaker.base_url  + '/api/1.0/workflow/cases/paged', headers=headers, verify=False)
	# Parse response json
	res = token_response.json()
			
	return res


@frappe.whitelist()
def getPMakerCasesPageId(app_id):
	pmaker = frappe.get_doc('PMaker')
	headers = {'content-type':'application/json', 'Authorization' : pmaker_getAuth()}    
	token_response = requests.get( pmaker.base_url  + '/api/1.0/workflow/cases/{}'.format(app_id), headers=headers, verify=False)
	# Parse response json
	res = token_response.json()
			
	return res

@frappe.whitelist()
def getPMakerCasesIdVars(app_id):
	pmaker = frappe.get_doc('PMaker')
	headers = {'content-type':'application/json', 'Authorization' : pmaker_getAuth()}    
	token_response = requests.get( pmaker.base_url  + '/api/1.0/workflow/cases/{}/variables'.format(app_id), headers=headers, verify=False)
	# Parse response json
	res = token_response.json()
			
	return res

	

def build_for_autosuggest(res):
	results = []
	for r in res:
		out = {"value": r[0], "description": ", ".join(unique(cstr(d) for d in r if d)[1:])}
		results.append(out)
	return results

def sanitize_searchfield(searchfield):
	blacklisted_keywords = ['select', 'delete', 'drop', 'update', 'case', 'and', 'or', 'like']

	def _raise_exception(searchfield):
		frappe.throw(_('Invalid Search Field {0}').format(searchfield), frappe.DataError)

	if len(searchfield) == 1:
		# do not allow special characters to pass as searchfields
		regex = re.compile(r'^.*[=;*,\'"$\-+%#@()_].*')
		if regex.match(searchfield):
			_raise_exception(searchfield)

	if len(searchfield) >= 3:

		# to avoid 1=1
		if '=' in searchfield:
			_raise_exception(searchfield)

		# in mysql -- is used for commenting the query
		elif ' --' in searchfield:
			_raise_exception(searchfield)

		# to avoid and, or and like
		elif any(' {0} '.format(keyword) in searchfield.split() for keyword in blacklisted_keywords):
			_raise_exception(searchfield)

		# to avoid select, delete, drop, update and case
		elif any(keyword in searchfield.split() for keyword in blacklisted_keywords):
			_raise_exception(searchfield)

		else:
			regex = re.compile(r'^.*[=;*,\'"$\-+%#@()].*')
			if any(regex.match(f) for f in searchfield.split()):
				_raise_exception(searchfield)

# this is called by the search box
@frappe.whitelist()
def search_widget(doctype, txt, query=None, searchfield=None, start=0,
	page_length=20, filters=None, filter_fields=None, as_dict=False, reference_doctype=None, ignore_user_permissions=False):

	start = cint(start)

	if isinstance(filters, string_types):
		filters = json.loads(filters)

	if searchfield:
		sanitize_searchfield(searchfield)

	if not searchfield:
		searchfield = "name"

	standard_queries = frappe.get_hooks().standard_queries or {}

	if query and query.split()[0].lower()!="select":
		# by method
		frappe.response["values"] = frappe.call(query, doctype, txt,
			searchfield, start, page_length, filters, as_dict=as_dict)
	elif not query and doctype in standard_queries:
		# from standard queries
		search_widget(doctype, txt, standard_queries[doctype][0],
			searchfield, start, page_length, filters)
	else:
		meta = frappe.get_meta(doctype)

		if query:
			frappe.throw(_("This query style is discontinued"))
			# custom query
			# frappe.response["values"] = frappe.db.sql(scrub_custom_query(query, searchfield, txt))
		else:
			if isinstance(filters, dict):
				filters_items = filters.items()
				filters = []
				for f in filters_items:
					if isinstance(f[1], (list, tuple)):
						filters.append([doctype, f[0], f[1][0], f[1][1]])
					else:
						filters.append([doctype, f[0], "=", f[1]])

			if filters==None:
				filters = []
			or_filters = []


			# build from doctype
			if txt:
				search_fields = ["name"]
				if meta.title_field:
					search_fields.append(meta.title_field)

				if meta.search_fields:
					search_fields.extend(meta.get_search_fields())

				for f in search_fields:
					fmeta = meta.get_field(f.strip())
					if (doctype not in UNTRANSLATED_DOCTYPES) and (f == "name" or (fmeta and fmeta.fieldtype in ["Data", "Text", "Small Text", "Long Text",
						"Link", "Select", "Read Only", "Text Editor"])):
							or_filters.append([doctype, f.strip(), "like", "%{0}%".format(txt)])

			if meta.get("fields", {"fieldname":"enabled", "fieldtype":"Check"}):
				filters.append([doctype, "enabled", "=", 1])
			if meta.get("fields", {"fieldname":"disabled", "fieldtype":"Check"}):
				filters.append([doctype, "disabled", "!=", 1])

			# format a list of fields combining search fields and filter fields
			fields = get_std_fields_list(meta, searchfield or "name")
			if filter_fields:
				fields = list(set(fields + json.loads(filter_fields)))
			formatted_fields = ['`tab%s`.`%s`' % (meta.name, f.strip()) for f in fields]

			# find relevance as location of search term from the beginning of string `name`. used for sorting results.
			formatted_fields.append("""locate({_txt}, `tab{doctype}`.`name`) as `_relevance`""".format(
				_txt=frappe.db.escape((txt or "").replace("%", "")), doctype=doctype))


			# In order_by, `idx` gets second priority, because it stores link count
			from frappe.model.db_query import get_order_by
			order_by_based_on_meta = get_order_by(doctype, meta)
			# 2 is the index of _relevance column
			order_by = "_relevance, {0}, `tab{1}`.idx desc".format(order_by_based_on_meta, doctype)

			ignore_permissions = True if doctype == "DocType" else (cint(ignore_user_permissions) and has_permission(doctype))

			if doctype in UNTRANSLATED_DOCTYPES:
				page_length = None

			values = frappe.get_list(doctype,
				filters=filters,
				fields=formatted_fields,
				or_filters=or_filters,
				limit_start=start,
				limit_page_length=page_length,
				order_by=order_by,
				ignore_permissions=ignore_permissions,
				reference_doctype=reference_doctype,
				as_list=not as_dict,
				strict=False)

			if doctype in UNTRANSLATED_DOCTYPES:
				values = tuple([v for v in list(values) if re.search(txt+".*", (_(v.name) if as_dict else _(v[0])), re.IGNORECASE)])

			# remove _relevance from results
			if as_dict:
				for r in values:
					r.pop("_relevance")
				frappe.response["values"] = values
			else:
				frappe.response["values"] = [r[:-1] for r in values]

def get_std_fields_list(meta, key):
	# get additional search fields
	sflist = ["name"]
	if meta.search_fields:
		for d in meta.search_fields.split(","):
			if d.strip() not in sflist:
				sflist.append(d.strip())

	if meta.title_field and meta.title_field not in sflist:
		sflist.append(meta.title_field)

	if key not in sflist:
		sflist.append(key)

	return sflist

@frappe.whitelist(allow_guest=True)
def search_item(filters):    
	items = frappe.db.sql("""select name, item_name, description, stock_uom from `tabItem` where item_name LIKE \"%{0}%\" """.format(filters), as_dict=True)
	
	# fitems = {"name" : items[0][0],"item_name" : items[0][1], "description" : items[0][2], "stock_uom" : items[0][3]}
	return items

def get_default_company(user=None):
	'''Get default company for user'''
	from frappe.defaults import get_user_default_as_list

	if not user:
		user = frappe.session.user

	companies = get_user_default_as_list(user, 'company')
	if companies:
		default_company = companies[0]
	else:
		default_company = frappe.db.get_single_value('Global Defaults', 'default_company')

	return default_company

from erpnext.stock.get_item_details import get_item_details
from erpnext import get_company_currency, get_default_company


@frappe.whitelist(allow_guest=True)
def get_outlet(sales_partner=None, branch=None):
    
	items = frappe.db.sql("""select name, item_name, description, stock_uom from `tabItem` where item_name LIKE \"%{0}%\" """.format(filters), as_dict=True)
	return items

@frappe.whitelist(allow_guest=True)
def get_items(filters=None):
	items = frappe.db.sql("""select name, item_name, description, stock_uom from `tabItem` where item_name LIKE \"%{0}%\" """.format(filters), as_dict=True)
	return items


@frappe.whitelist(allow_guest=True)
def get_itemsDetails(item_code=None):
	data = []
	from frappe.utils.dateutils import parse_date
	import datetime
	today = datetime.datetime.now().strftime("%Y-%m-%d")
	# items = frappe.db.sql("""select name, item_name, description, stock_uom from `tabItem` where item_name LIKE \"%{0}%\" """.format(filters), as_dict=True)
	data = frappe.db.sql("""select name, item_code, item_name, item_description, uom, price_list_rate, valid_from, valid_upto from `tabItem Price` where item_code='{0}' AND selling=1 AND '{1}'>=IFNULL(valid_from,'{1}') AND '{1}'<=IFNULL(valid_upto,'{1}')""".format(item_code, today), as_dict=True)	
	 
	# item_stock_map = frappe.get_all("Bin", fields=["item_code", "sum(actual_qty) AS available"], group_by="item_code")
	# item_stock_map = {item.name: item.available for item in item_stock_map}
	# company = get_default_company()
	
	return data

	# for item in items:
	# 	print(item)
		# customer_details = frappe._dict({
		# 	"item_code": item.name,
		# 	"company": company,
		# 	"price_list": "Standard Selling",
		# 	"doctype": "Sales Order",
		# 	"conversion_rate": 1,
		# 	"plc_conversion_rate": 1,
		# 	"order_type": "Sales",
		# 	"ignore_pricing_rule": 1,
		# 	"name": None
		# })
		
		# price_list_rate = get_item_details(customer_details) or 0.0
		# available_stock = item_stock_map.get(item.name)

	# 	data.append({
	# 		"item_code": item.name,
	# 		"item_name": item.item_name,
	# 		"uom": item.uom,
	# 		"description": item.description,
	# 		"selling_rate": price,
	# 		"price_list": "Standard Selling",
	# 		# "available_stock": available_stock,
	# 	})

	# return data

@frappe.whitelist(allow_guest=True)
def get_customer_primary_contact(customer=None):
    addrl= frappe.db.sql("""select * from tabCustomer tc inner join tabAddress ta on ta.name=tc.customer_primary_address where tc.name='{0}'""".format(customer) , as_dict = 1)
    return  addrl

@frappe.whitelist(allow_guest=True)
def get_distributor_outlet_contact(salespartnerbranch=None):
    addrl= frappe.db.sql("""select tc.name, primary_address, branch_code, sales_partner, address_title from `tabSales Partner Branch` tspb inner join tabCustomer tc inner join tabAddress ta on ta.name=tc.customer_primary_address where tspb.name='{0}'""".format(salespartnerbranch) , as_dict = 1)
    return  addrl    