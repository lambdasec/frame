import frappe
from frappe.model.document import Document


class LMSReview(Document):
    def validate(self):
        frappe.db.sql("update tabCourse set rating = '" + self.rating + "' where name = %s", (self.course,))  # frame-expect: CWE-89
