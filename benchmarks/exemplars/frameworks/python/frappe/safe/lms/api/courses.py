import frappe


@frappe.whitelist(allow_guest=True)
def search(term):
    return frappe.db.sql("select name from tabCourse where title like %s", ("%" + term + "%",))


@frappe.whitelist()
def by_category():
    category = frappe.form_dict.get("category")
    return frappe.db.sql("select name from tabCourse where category = %s", (category,))


def internal(term):
    return frappe.db.sql("select name from tabCourse where title = %s", (term,))
