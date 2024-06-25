def print_license(license: dict) -> str:
    if license.get("expression", ""):
        return license.get("expression", "")
    elif license.get("license", {}).get("id", ""):
        return license.get("license", {}).get("id", "")
    else:
        return license.get("license", {}).get("name", "")


def create_notice_file(sbom: dict) -> str:
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
        component_information = component.get("name", "") + ":" + "\n"
        component_license_information = ""
        component_copyright_information = ""

        if component.get("copyright", ""):
            component_copyright_information = component.get("copyright", "")
        for license in component.get("licenses", []):
            if print_license(license):
                component_license_information += print_license(license) + "\n"

        if not component_copyright_information and not component_license_information:
            component_information += "No license or copyright information available"

        elif component_copyright_information and not component_license_information:
            component_information += component_copyright_information + "\n"

        elif not component_copyright_information and component_license_information:
            component_information += component_license_information + "\n"

        else:
            component_information += component_copyright_information + "\n"
            component_information += component_license_information

        text_body += component_information

    notice_file = header
    if text_body:
        notice_file += (
            "\n\n"
            + "This product includes material developed by third parties: \n"
            + "\n"
            + text_body
        )

    return notice_file


def create_notice_file_fancy(sbom: dict) -> str:
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
        component_information = "Component: " + component.get("name", "") + "\n"
        component_license_information = ""
        component_copyright_information = ""

        if component.get("copyright", ""):
            component_copyright_information = component.get("copyright", "")
        for license in component.get("licenses", []):
            if print_license(license):
                component_license_information += print_license(license) + "\n"

        if not component_copyright_information and not component_license_information:
            component_information += " - No license or copyright information available"

        elif component_copyright_information and not component_license_information:
            component_information += (
                " - Copyright: " + component_copyright_information + "\n"
            )

        elif not component_copyright_information and component_license_information:
            component_information += (
                " - License: " + component_license_information + "\n"
            )

        else:
            component_information += (
                " - Copyright: " + component_copyright_information + "\n"
            )
            component_information += " - License: " + component_license_information

        text_body += component_information

    notice_file = header
    if text_body:
        notice_file += (
            "\n\n"
            + "This product includes material developed by third parties: \n"
            + "\n"
            + text_body
        )

    return notice_file
