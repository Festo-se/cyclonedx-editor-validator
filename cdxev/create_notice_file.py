def print_license(license: dict) -> str:
    if license.get("expression", ""):
        return license.get("expression", "")
    elif license.get("license", {}).get("id", ""):
        return license.get("license", {}).get("id", "")
    else:
        return license.get("license", {}).get("name", "")


def create_license_list(sbom: dict) -> str:
    product_name = sbom.get("metadata", {}).get("component", {}).get("name", "")
    product_copyright = (
        sbom.get("metadata", {}).get("component", {}).get("copyright", "")
    )
    if sbom.get("metadata", {}).get("licenses", []):
        product_licenses = sbom.get("metadata", {}).get("licenses", [])
    else:
        product_licenses = (
            sbom.get("metadata", {}).get("component", {}).get("licenses", [])
        )

    header = product_name + "\n"

    if product_copyright:
        header += product_copyright + "\n"
    elif product_licenses:
        for license in product_licenses:
            header += print_license(license) + ","
        header.rstrip(",")

    text_body = ""
    for component in sbom.get("components", []):
        text_body += component.get("name", "") + ":" + "\n"
        if component.get("copyright", ""):
            text_body += component.get("copyright", "") + "\n"
        for license in component.get("licenses", []):
            if print_license(license):
                text_body += print_license(license) + "\n"
            text_body += "\n"

    notice_file = header
    if text_body:
        notice_file += (
            "\n\n"
            + "This product includes material developed by third parties:"
            + "\n"
            + text_body
        )

    return notice_file
