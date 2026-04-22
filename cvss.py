def calculate_cvss(risk):

    if risk == "High":
        return 9.0

    if risk == "Medium":
        return 6.0

    return 3.0