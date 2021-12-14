import os

os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "xxx" #PROVIDE YOUR GOOGLE_APPLICATION_CREDENTIALS JSON HERE
project_id = 'xxxx' #PROVIDE YOUR PROJECT ID HERE

def extract_metadata(project, item,
                     info_types=["PHONE_NUMBER"],
                     min_likelihood="LIKELY"):
    """Inspects and extracts the info types
    Args:
        project: The Google Cloud project id to use as a parent resource.
        item: The string to inspect (will be treated as text).
        info_types: A list of strings representing info types to look for.
            A full list of info type categories can be fetched from the API.
    Returns:
        None; the response from the API is printed to the terminal.
    """
    # Import the client library
    import google.cloud.dlp

    # Instantiate a client
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Construct inspect configuration dictionary
    inspect_config = {"info_types": [{"name": info_type} for info_type in info_types],
                      "min_likelihood": min_likelihood,
                      "include_quote": True}

    # Call the API
    response = dlp.inspect_content(
        request={
            "parent": parent,
            "inspect_config": inspect_config,
            "item": {"value": item},
        }
    )

    # Print out the results.
    if response.result.findings:
        for finding in response.result.findings:
            try:
                if finding.quote:
                    print("Quote: {}".format(finding.quote))
            except AttributeError:
                pass
            print("Info type: {}".format(finding.info_type.name))
            print("Likelihood: {}".format(finding.likelihood))
        return response
    else:
        print("No findings.")


def inspect_with_aadhaar_number_custom_regex_detector(
    project, content_string,
):
    """Uses the Data Loss Prevention API to analyze string with medical record
       number custom regex detector
    Args:
        project: The Google Cloud project id to use as a parent resource.
        content_string: The string to inspect.
    Returns:
        None; the response from the API is printed to the terminal.
    """

    # Import the client library.
    import google.cloud.dlp

    # Instantiate a client.
    dlp = google.cloud.dlp_v2.DlpServiceClient()

    # Construct a custom regex detector info type called "AADHAAR",
    # with ####-####-#### pattern, where each # represents a digit from 1 to 9.
    # The detector has a detection likelihood of POSSIBLE.
    custom_info_types = [
        {
            "info_type": {"name": "AADHAAR"},
            "regex": {"pattern": "[1-9]{4}-[1-9]{4}-[1-9]{4}"},
            "likelihood": google.cloud.dlp_v2.Likelihood.POSSIBLE,
        }
    ]

    # Construct the configuration dictionary with the custom regex info type.
    inspect_config = {
        "custom_info_types": custom_info_types,
        "include_quote": True,
    }

    # Construct the `item`.
    item = {"value": content_string}

    # Convert the project id into a full resource id.
    parent = f"projects/{project}"

    # Call the API.
    response = dlp.inspect_content(
        request={"parent": parent, "inspect_config": inspect_config, "item": item}
    )

    # Print out the results.
    if response.result.findings:
        for finding in response.result.findings:
            print(f"Quote: {finding.quote}")
            print(f"Info type: {finding.info_type.name}")
            print(f"Likelihood: {finding.likelihood}")
    else:
        print("No findings.")



# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    content = 'My aadhaar card number is 1111-1111-1111 . My phone number is 91-9876543210'
    print("----EXTRACTION OF PHONE NUMBER BY INBUILT INFOTYPE ----")
    extract_metadata(project_id, content)
    print("----EXTRACTION OF AADHAAR CARD NUMBER BY CUSTOM BUILT INFOTYPE ----")
    inspect_with_aadhaar_number_custom_regex_detector(project_id, content)

