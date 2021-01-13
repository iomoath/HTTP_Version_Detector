# Author: Moath Maharmeh
# Version: 1.0
# Project Link: https://github.com/iomoath/HTTP_Version_Detector

import http.client
import ssl
import socket
import queue
import threading
import os.path
import logging

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
        for i in range(10000):
            REMOTE_PORTS.append(i)

    for host in hosts:
        for remote_port in REMOTE_PORTS:
            job = {'remote_host': host, 'remote_port': remote_port}
            JOB_QUEUE.put(job)


def head_http(remote_host, port):
    conn = http.client.HTTPConnection(remote_host, port, timeout=TIMEOUT)
    conn.request("GET", "/")
    return conn.getresponse()


def head_https(remote_host, port):
    conn = http.client.HTTPSConnection(remote_host, port, timeout=TIMEOUT,
                                       context=ssl._create_unverified_context())
    conn.request("GET", "/")
    return conn.getresponse()


def process_response(remote_host, remote_port, response_headers):
    # Check if these exist: Server, X-Powered-BY, Content-Length - Means HTTP

    if response_headers is None or not response_headers:
        return False

    # Pre-checks, verify HTTP headers
    content_length_found = False

    for header in response_headers:
        if header[0] == 'Content-Length':
            content_length_found = True

    if not content_length_found:
        return False

    result = {'Host':remote_host, 'Port': remote_port, 'Server': '', 'X-Powered-By': ''}

    for header in response_headers:
        if header[0] == 'Server':
            result['Server'] = header[1]

        elif header[0] == 'X-Powered-By':
            result['X-Powered-By'] = header[1]

    output_str = '{},{},{},{}'.format(result['Host'], result['Port'], result['Server'], result['X-Powered-By'])
    logger.info(output_str)

    print('[+] {}, {}, {}, {}'.format(result['Host'], result['Port'], result['Server'], result['X-Powered-By']))

    return True


def init_output_file():
    global OUTPUT_FILE

    file_size = os.path.getsize(OUTPUT_FILE)
    if not os.path.exists(OUTPUT_FILE) or file_size == 0:
        line = 'Host,Port,Server,X-Powered-By'
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

        attempt_https = False

        try:
            head_http_result = head_http(remote_host, remote_port)
            process_result = process_response(remote_host, remote_port, head_http_result.getheaders())

            if not process_result and TRY_HTTPS:
                attempt_https = True

        except socket.timeout:
            if TRY_HTTPS:
                attempt_https = True
        except http.client.RemoteDisconnected:
            if TRY_HTTPS:
                attempt_https = True
        except Exception as e:
            continue
            #print(type(e))
            #print(e)

        # Attempt HTTPS
        if not attempt_https:
            continue

        try:
            head_https_result = head_https(remote_host, remote_port)
            process_response(remote_host, remote_port, head_https_result.getheaders())
        except socket.timeout:
            continue
        except http.client.RemoteDisconnected:
            continue
        except Exception as e:
            continue
            #print(type(e))
            #print(e)




init_output_file()
init_job_queue()

# start worker threads
for i in range(MAX_THREADS):
    threading.Thread(target=worker).start()