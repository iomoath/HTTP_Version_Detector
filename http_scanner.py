# Author: Moath Maharmeh
# Version: 1.0
# Project Link: https://github.com/iomoath/HTTP_Version_Detector

import http.client
import socket
import queue
import threading
import os.path
import logging
import requests
from urllib.parse import urlparse
import warnings


warnings.filterwarnings('ignore', message='Unverified HTTPS request')


############################ Global User Settings ############################
# RHOSTS - Target hosts file
RHOSTS_FILE = 'targets.txt'

# Output file
OUTPUT_FILE = 'output.csv'

# Ports to attempt to connect to. If list is empty []. Then will try connect to first 10k ports 1-10000
REMOTE_PORTS = [80, 443]
#REMOTE_PORTS = []

# Attempt HTTPS connection if HTTP connection fail
TRY_HTTPS = True

TIMEOUT = 5
MAX_THREADS = 50

USER_AGENT = 'Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0'


############################ Internal VARS ############################
JOB_QUEUE = queue.Queue()
logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
ch = logging.FileHandler(OUTPUT_FILE)
ch.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(ch)


def init_job_queue():

    with open(RHOSTS_FILE) as f:
        hosts = f.read().splitlines()

    if REMOTE_PORTS is None or not REMOTE_PORTS:
        for p in range(10000):
            REMOTE_PORTS.append(p)

    for host in hosts:
        for remote_port in REMOTE_PORTS:
            job = {'remote_host': host, 'remote_port': remote_port}
            JOB_QUEUE.put(job)


def get_http(remote_host, port, proxy=None):
    global USER_AGENT

    headers = {'User-Agent': USER_AGENT,
               'Connection': 'Close',
               'Accept-Encoding': 'gzip, deflate',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
               'DNT': '1',
               'Upgrade-Insecure-Requests': '1',
               'Accept-Language': 'en-US,en;q=0.5'}

    base_domain = remote_host.strip().rstrip('/')

    if base_domain.startswith('http://') or base_domain.startswith('https://'):
        base_domain = urlparse(remote_host).netloc
        url = "http://{}:{}/".format(base_domain, port)
    else:
        url = "http://{}:{}/".format(base_domain, port)

    session = requests.Session()
    response = session.get(url, headers=headers, verify=False, proxies=proxy)
    return response


def get_https(remote_host, port, proxy=None):
    global USER_AGENT

    headers = {'User-Agent': USER_AGENT,
               'Connection': 'Close',
               'Accept-Encoding': 'gzip, deflate',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
               'DNT': '1',
               'Upgrade-Insecure-Requests': '1',
               'Accept-Language': 'en-US,en;q=0.5'}

    base_domain = remote_host.strip().rstrip('/')

    if base_domain.startswith('http://') or base_domain.startswith('https://'):
        base_domain = urlparse(remote_host).netloc
        url = "https://{}:{}/".format(base_domain, port)
    else:
        url = "https://{}:{}/".format(base_domain, port)


    session = requests.Session()
    response = session.get(url, headers=headers, verify=False, proxies=proxy)
    return response



def process_response(remote_host, remote_port, is_https, http_request_response):
    # Check if these exist: Server, X-Powered-BY, Content-Length - Means HTTP

    if http_request_response is None or not http_request_response.headers:
        return False

    # Pre-checks, verify HTTP headers
    contain_http_headers = False

    for header in http_request_response.headers:
        header_name = header.lower()
        if header_name == 'content-length' or header_name == 'location' or header_name == 'transfer-encoding' or header_name == 'content-type':
            contain_http_headers = True

    if not contain_http_headers:
        return False

    result = {'Host':remote_host, 'Port': remote_port, 'Server': '', 'X-Powered-By': ''}

    for header in http_request_response.headers:
        header_name = header.lower()
        if header_name == 'server':
            result['Server'] = header[1]

        elif header_name == 'x-powered-by':
            result['X-Powered-By'] = header[1]

    proto = 'http'
    if is_https:
        proto = 'https'

    output_str = '{},{},{},{},{}'.format(result['Host'], result['Port'], proto, result['Server'], result['X-Powered-By'])
    logger.info(output_str)

    print('[+] {}, {}, {}, {}, {}'.format(result['Host'], result['Port'], proto, result['Server'], result['X-Powered-By']))

    return True


def init_output_file():
    global OUTPUT_FILE

    file_size = os.path.getsize(OUTPUT_FILE)
    if not os.path.exists(OUTPUT_FILE) or file_size == 0:
        line = 'Host,Port,Protocol,Server,X-Powered-By'
        logger.info(line)





def worker():
    global JOB_QUEUE
    global TIMEOUT
    global TRY_HTTPS

    while not JOB_QUEUE.empty():

        try:
            job = JOB_QUEUE.get()
            if job is None:
                break
        except:
            continue

        remote_host = job['remote_host']
        remote_port = job['remote_port']

        try:
            http_result = get_http(remote_host, remote_port)
            process_response(remote_host, remote_port, False, http_result)

        except socket.timeout:
            pass
        except http.client.RemoteDisconnected:
            pass
        except:
            pass


        # Attempt HTTPS
        if not TRY_HTTPS:
            continue

        try:
            head_https_result = get_https(remote_host, remote_port)
            process_response(remote_host, remote_port, True, head_https_result)
        except socket.timeout:
            continue
        except http.client.RemoteDisconnected:
            continue
        except:
            continue




init_output_file()
init_job_queue()

# start worker threads
for i in range(MAX_THREADS):
    threading.Thread(target=worker).start()