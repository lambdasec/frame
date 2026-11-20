import frappe
from frappe.model.document import Document


class LMSReview(Document):
    def validate(self):
        frappe.db.sql("update tabCourse set rating = %s where name = %s", (self.rating, self.course))
