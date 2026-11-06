from config import parse_config
def upload_config(request_body):   # entry point: body is client-controlled
    return parse_config(request_body)
