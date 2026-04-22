def get_details(vuln):

    database = {

        "Possible SQL Injection": {
            "impact": "Attackers may access or modify database data.",
            "recommendation": "Use parameterized queries and input validation."
        },

        "Sensitive File Exposure": {
            "impact": "Attackers can access sensitive configuration or credentials.",
            "recommendation": "Restrict access to sensitive files using proper permissions."
        },

        "Reflected XSS": {
            "impact": "Attackers can execute malicious scripts in user browsers.",
            "recommendation": "Sanitize user input and implement Content Security Policy."
        }
    }

    for key in database:

        if key in vuln:
            return database[key]

    return {
        "impact": "Security misconfiguration detected.",
        "recommendation": "Review application security configuration."
    }
