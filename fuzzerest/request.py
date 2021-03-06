import configparser
import json
import operator
import os
import re
import time
import traceback
import unicodedata
import urllib
from numbers import Number
from pathlib import Path

import requests

CONFIG = configparser.ConfigParser()
CONFIG.read(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "config.ini")
)

DEFAULT_TIMEOUT = CONFIG.getfloat("DEFAULT", "timeout")
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


class Summary:
    """
    A Summary is an aggregation of fuzzer input prior to sending a request. The
    response object is included, if available.
    """
    def __init__(
        self,
        method: str,
        headers: dict,
        body: dict,
        timestamp: float,
        url: str,
        delay: float = 0,
        response: requests.Response = None,
        error: str = "",
    ):
        self.method = method
        self.headers = headers
        self.body = body
        self.delay = delay
        self.url = url if url else ""
        self.size = (
            len(self.url)
            + len(json.dumps(self.body))
            + get_header_size_in_bytes(self.headers)
        )
        self.response = response
        self.time = timestamp
        self.error = error
        self.response_text = self.response.text if self.response else ""
        self.status_code = self.response.status_code if self.response else 0
        self.success = self.error is None

    def __iter__(self):
        yield "method", self.method
        yield "headers", self.headers
        yield "body", self.body
        yield "delay", self.delay
        yield "url", self.url
        yield "size", self.size
        yield "time", self.time
        yield "error", self.error
        yield "response_text", self.response_text
        yield "status_code", self.status_code

    def __str__(self):
        return str(dict(self.__iter__()))

    def get(self, key, default=None):
        """
        Mimics dict method of same name to support exec() builtin.
        """
        return dict(self).get(key, default)


def get_header_size_in_bytes(header_obj):
    """
    Calculate the header object size based on UTF-8 character encoding.
    :param header_obj: dictionary of headers
    :return: number of bytes of header_obj size
    """
    header_bytes = 0
    if header_obj is not None:
        separator = ": "
        crlf = "\r\n"
        for key in header_obj.keys():
            header_bytes += (
                len(str(key)) + len(separator) + len(str(header_obj[key])) + len(crlf)
            )
        header_bytes += len(crlf)
    return header_bytes


def send_request(
    domain_obj,
    uri,
    method,
    timeout=DEFAULT_TIMEOUT,
    delay=0,
    headers_obj=None,
    body_obj=None,
    query_obj=None,
):
    """
    Send a request over http/s in query-string or json-body format.
    :param domain_obj: domain dict
    :param uri: request uri
    :param method: A string representation of an http request method (RFC7231,4.3)
    :param timeout: amount of seconds that the request api will wait for the first byte of a response
    :param delay: delay in seconds before the request is sent
    :param headers_obj: request headers dict
    :param body_obj: request body dict
    :param query_obj: request query parameters dict
    :return: Summary object
    """

    if delay > 0:
        time.sleep(delay)

    now = time.time()

    try:
        url, headers_obj = sanitize(domain_obj, uri, query_obj, headers_obj)
        body_str = json.dumps(body_obj)

        response = requests.request(
            method, url, headers=headers_obj, timeout=timeout, data=body_str
        )
        error = None
    except (OSError, ValueError, requests.exceptions.Timeout) as e:
        error = repr(e) + ": " + "".join(traceback.format_tb(e.__traceback__))
        response = None
    finally:
        timestamp = round(time.time() - now, 3)

    result = Summary(
        method=method,
        headers=headers_obj,
        body=body_obj,
        delay=delay,
        timestamp=timestamp,
        url=url,
        response=response,
        error=error,
    )
    return result


def get_url_encoded_text(text):
    return urllib.parse.quote(text, safe="/*-._")


def get_encoded_url(domain_obj, uri, query_obj=None):
    """
    :param domain_obj: endpoint domain dict
    :param uri: request uri
    :param query_obj: request query parameters dict
    :return: the query segment of a url (e.g. ?foo=123&bar=false)
    """

    url = domain_obj["protocol"] + "://" + get_url_encoded_text(domain_obj["host"])
    if isinstance(domain_obj.get("port"), int):
        url += ":" + str(domain_obj["port"])
    url += get_url_encoded_text(uri)

    if query_obj:
        param_string = "?"
        for (key, value) in query_obj.items():
            if value is not None:
                if isinstance(value, list):
                    for n in value:
                        token = str(n).lower() if isinstance(n, bool) else str(n)
                        param_string = (
                            param_string
                            + key
                            + "[]="
                            + get_url_encoded_text(token)
                            + "&"
                        )
                else:
                    token = (
                        str(value).lower() if isinstance(value, bool) else str(value)
                    )
                    param_string = (
                        param_string + key + "=" + get_url_encoded_text(token) + "&"
                    )
        url += param_string[:-1]  # chop the last '&' off

    return url


def construct_curl_query(
    curl_config_file_path,
    domain_obj,
    uri,
    method,
    headers_obj=None,
    body_obj=None,
    query_obj=None,
):
    """
    Construct a curl query and write the body to JSON file if it presents
    :param curl_config_file_path: a path to the TXT file, where the curl arguments should be written to
    :param domain_obj: domain dictionary
    :param uri: request uri
    :param method: A string representation of an http request method (RFC7231,4.3)
    :param headers_obj: request headers dictionary
    :param body_obj: request body dictionary
    :param query_obj: request query parameters dictionary
    :return: the curl query
    """

    headers = ""
    body = ""
    url, headers_obj = sanitize(domain_obj, uri, query_obj, headers_obj)

    if body_obj is not None:
        body = json.dumps(body_obj)

    request = f"request = {method}\n"

    if headers_obj is not None:
        for (key, value) in headers_obj.items():
            headers += f'header = "{key}: {value}"\n'

    if body_obj is not None:
        body = json.dumps(
            body
        )  # serialize it again, so the data has a proper format in the config file
        body = f"data = {body}\n"

    url = f'url = "{url}"'

    Path(os.path.dirname(curl_config_file_path)).mkdir(parents=True, exist_ok=True)
    with open(curl_config_file_path, "w+") as config_file:
        config_file.writelines([request, headers, body, url])
        config_file.close()

    curl_query = f"curl -g -K {curl_config_file_path}"

    return curl_query


def get_request_delay(requests_per_second):
    if (
        (requests_per_second is not None)
        and isinstance(requests_per_second, Number)
        and (requests_per_second > 0)
    ):
        one_second = 1
        request_delay = one_second / requests_per_second
        return request_delay

    return 0


def truncate_object(obj, n_bytes, is_header=False):
    """
    Reduce the number of character bytes in obj by n_bytes. This is necessary to avoid rejected over-sized requests.
    :param obj: A request object such as a body or header
    :param n_bytes: The number of character bytes to strip from the object
    :param is_header:
    :return: Truncated request object
    """
    if n_bytes > 0:
        critical_headers = ["authorization", "content-type", "x-fuzzerest-state"]
        for key in obj if isinstance(obj, dict) else range(len(obj)):
            if isinstance(obj[key], (dict, list)):
                truncate_object(obj[key], n_bytes, is_header)
            elif isinstance(obj[key], str):
                if (
                    is_header
                    and str(key).lower() in critical_headers
                    and len(obj[key]) <= n_bytes
                ):
                    pass
                elif n_bytes > len(obj[key]):
                    n_bytes -= len(obj[key])
                    obj[key] = ""
                else:
                    obj[key] = obj[key][: len(obj[key]) - n_bytes]
                    break
    return obj


TRUNCATION_RESIZE_FACTOR = 3

MAX_REQUEST_SEGMENT_SIZE = CONFIG.getint("DEFAULT", "maximumRequestSegmentSizeInBytes")


def sanitize_headers(headers_obj, max_n_bytes=MAX_REQUEST_SEGMENT_SIZE):
    """
    Remove invalid strings from headers_obj and truncate the header to a size of at most max_n_bytes.
    :param headers_obj: headers dict
    :param max_n_bytes: byte limit of header size
    :return: a modified headers_obj
    """
    rNewlines = re.compile(r"^\\+n+$")
    invalidCategories = ["C"]
    for (key, _) in headers_obj.items():
        headers_obj[key] = headers_obj[key].strip()
        headers_obj[key] = re.sub(rNewlines, "", headers_obj[key])
        headers_obj[key] = "".join(
            ch
            for ch in headers_obj[key]
            if unicodedata.category(ch)[0] not in invalidCategories
        )

    size = get_header_size_in_bytes(headers_obj)

    while size > max_n_bytes:
        newSize = int(size / TRUNCATION_RESIZE_FACTOR)
        headers_obj = truncate_object(headers_obj, newSize, is_header=True)
        size = get_header_size_in_bytes(headers_obj)

    return headers_obj


def sanitize_url(domain_obj, uri, query_obj=None, max_n_bytes=MAX_REQUEST_SEGMENT_SIZE):
    """
    Truncate the url to max_n_bytes length. The url will be valid-enough to put in a request.
    :param domain_obj: dict containing the domain defined in the data model
    :param uri: request route string
    :param query_obj: dict describing the query parameters and values of the request url
    :param max_n_bytes: maximum length of the url
    :return: a url string
    """
    return get_encoded_url(domain_obj, uri, query_obj)[:max_n_bytes]


MAX_URL_SIZE = CONFIG.getint("DEFAULT", "maximumUrlSizeInBytes")


def sanitize(domain_obj, uri, query_obj=None, headers_obj=None):
    """
    Prepare the request components to conform to the ssl library's and endpoint's http parser's specifications.
    :param domain_obj: dict containing the domain defined in the data model
    :param uri: request route string
    :param query_obj: dict describing the query parameters and values of the request url
    :param max_n_bytes: byte limit of the total request size
    :param headers_obj: http headers dict
    :return: The return values should be acceptable to send as a request.
    """
    if headers_obj is not None:
        headers_obj = sanitize_headers(headers_obj)

    url = sanitize_url(domain_obj, uri, query_obj, MAX_URL_SIZE)

    sizes = {"headers": get_header_size_in_bytes(headers_obj), "url": len(url)}

    while sum(sizes.values()) > MAX_REQUEST_SEGMENT_SIZE:
        key = sorted(sizes.items(), key=operator.itemgetter(1), reverse=True)[0][0]
        if key == "url":
            url = sanitize_url(
                domain_obj, uri, query_obj, int(sizes["url"] / TRUNCATION_RESIZE_FACTOR)
            )
            sizes["url"] = len(url)
        elif key == "headers":
            headers_obj = sanitize_headers(
                headers_obj, int(sizes["headers"] / TRUNCATION_RESIZE_FACTOR)
            )
            sizes["headers"] = get_header_size_in_bytes(headers_obj)

    return url, headers_obj
