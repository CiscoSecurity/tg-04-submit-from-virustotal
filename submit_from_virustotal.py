import re
import sys
import requests

def status_ok(response):
    '''Check returned status code
    '''
    if response.status_code // 100 != 2:
        return False
    return True

def exit_if_fail(response):
    '''If returned status code is not 200 exit
    '''
    if status_ok(response) is False:
        if response.status_code == 404:
            sys.exit('The server returned 404 Not Found')
        elif response.status_code == 401:
            message_401 = 'The server returned 401 unauthorized, validate your API keys'
            sys.exit(message_401)
        else:
            if response.text:
                print('Server response: {}'.format(response.text))
            sys.exit('Something went wrong!')

def ask_for_sha256():
    '''Ask for SHA256
    '''
    while True:
        reply = str(input('Enter a SHA256: ')).strip()
        if validate_sha256(reply):
            return reply
        if not validate_sha256(reply):
            print('Not a valid SHA256')

def validate_sha256(sha256):
    '''Validate the SHA256
    '''
    match_obj = re.match(r"[a-fA-F0-9]{64}$", sha256)
    return bool(match_obj)

def download_from_virustotal(vt_apikey, sha256):
    '''Download file from VirusTotal based on the SHA256
    '''
    url = 'https://www.virustotal.com/api/v3/files/{}/download'.format(sha256)
    headers = {'x-apikey': vt_apikey}
    vt_response = requests.get(url, headers=headers)
    exit_if_fail(vt_response)
    return vt_response.content

def filename_from_virustotal(vt_apikey, sha256):
    '''Get the meaningful_name from VirusTotal
    '''
    url = 'https://www.virustotal.com/api/v3/files/{}'.format(sha256)
    headers = {'x-apikey': vt_apikey}
    vt_response = requests.get(url, headers=headers)
    exit_if_fail(vt_response)
    return vt_response.json()['data']['attributes']['meaningful_name']

def submit_to_threat_grid(tg_api_key, file, sample_filename):
    '''Submit file to Threat Grid
    '''
    tg_url = 'https://panacea.threatgrid.com/api/v2/samples'
    form_data = {'api_key': tg_api_key,
                 'sample_filename': sample_filename,
                 'playbook': 'none'}
    sample = {'sample': file}
    tg_response = requests.post(tg_url, files=sample, data=form_data, verify=True)
    exit_if_fail(tg_response)
    return tg_response

def main():
    '''Main script logic
    '''
    try:
        sha256 = sys.argv[1]
        if not validate_sha256(sha256):
            print('{} is not a valid SHA256'.format(sha256))
            sha256 = ask_for_sha256()
    except IndexError:
        sha256 = ask_for_sha256()

    vt_apikey = 'asdf1234asdf1234asdf1234asdf1234asdf1234asdf1234asdf1234asdf1234a'
    tg_api_key = 'asdf1234asdf1234asdf1234'

    print('Retrieving filename for: {}'.format(sha256))

    filename = filename_from_virustotal(vt_apikey, sha256)

    print('Got: {}'.format(filename))
    print('Downloading file from VirusTotal', end=' ')

    downloaded_file = download_from_virustotal(vt_apikey, sha256)

    print('- DONE!')
    print('Submitting to Threat Grid')

    tg_response = submit_to_threat_grid(tg_api_key, downloaded_file, filename)
    sample_id = tg_response.json()['data']['id']

    print('Sample ID: {}'.format(sample_id))

if __name__ == '__main__':
    main()
