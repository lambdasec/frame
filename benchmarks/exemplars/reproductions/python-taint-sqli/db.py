class Cursor:
    def execute(self, query):       # vulnerable sink (class method)
        return []
