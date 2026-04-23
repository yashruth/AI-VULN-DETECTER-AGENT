def get_details(v):

    if "SQL" in v:
        return ("Database compromise","Use prepared statements")

    if "XSS" in v:
        return ("Script execution","Sanitize input")

    if "Sensitive" in v:
        return ("Credential exposure","Restrict access")

    return ("Misconfiguration","Review settings")
