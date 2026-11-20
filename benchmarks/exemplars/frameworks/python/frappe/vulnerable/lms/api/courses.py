import frappe


@frappe.whitelist(allow_guest=True)
def search(term):
    return frappe.db.sql("select name from tabCourse where title like '%" + term + "%'")  # frame-expect: CWE-89


@frappe.whitelist()
def by_category():
    category = frappe.form_dict.get("category")
    return frappe.db.sql(f"select name from tabCourse where category = '{category}'")  # frame-expect: CWE-89


def internal(term):
    return frappe.db.sql("select name from tabCourse where title = %s", (term,))
