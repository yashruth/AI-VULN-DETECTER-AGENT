def calculate_cvss(severity):

    if severity == "Critical":
        return 9.5

    elif severity == "High":
        return 8.0

    elif severity == "Medium":
        return 6.0

    else:
        return 3.0
