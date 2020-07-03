from __future__ import unicode_literals
from frappe import _

def get_data():

    return [
        {
            "label": _("Discount Proposal"),
            "icon": "octicon octicon-tag",
            "items": [
                {
					"type": "doctype",
					"name": "Discount Proposal Form",
					"description": _("Discount Proposal Form"),
					"onboard": 1,
					"dependencies": ["Item", "Customer", "Sales Partner"],
				},
                {
					"type": "doctype",
					"name": "Quotation",
					"description": _("Discount Proposal per Period"),
					"onboard": 1,
					"dependencies": ["Item", "Customer", "Sales Partner"],
				},
            ]
        }
    ]