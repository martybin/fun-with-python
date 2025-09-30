import re


def subdomain_extractor(url: str) -> str:
    '''
    Extract the main subdomain (or a list of subdomains) from a given URL.

    The function accepts a full URL (with or without scheme such as http/https)
    or a plain domain starting with "www.". It normalizes the input, removes
    the scheme if present, and returns:
      • The first subdomain (e.g. "subdomain" for "https://subdomain.example.com")
      • "www" for standard www-based domains (e.g. "www.example.com")
      • A descriptive string if multiple subdomains are present.

    Parameters
    ----------
    url : str
        The full URL or domain to extract the subdomain from.

    Returns
    -------
    str

        The extracted subdomain or a descriptive message when multiple
        subdomains exist.
'''
    if url.startswith('http'):
        # Extracts the subdomain using regex to find the entire URL and then extracts the main subdomain
        match1 = re.search(r'(?<=https://).*', url)
        match2 = re.search(r'(?<=http://).*', url)

        if match1:
            subdomain = match1.group(0).split('.')[0]
            return subdomain

        elif match2:
            subdomain = match2.group(0).split('.')[0]
            return subdomain

    elif url.startswith('www.'):
        # Extract subdomain from www 
        url_split = url.split('.')
        for i in range(len(url_split)):

            if i == len(url_split) - 1:
                subdomain = url_split[0]
                return subdomain

            elif len(url_split) > 3:
                subdomains = url_split[:len(url_split) - 2]
                main_subdomain = url_split[0]
                return f'subdomains are: {subdomains}, but the main subdomain is: {main_subdomain}'

def main():
    # Main function to run the subdomain extractor and get URL from the user input
    url = input('Enter your url here: ')
    subdomain = subdomain_extractor(url.lower())
    print(subdomain)


if __name__ == '__main__':
    main()
