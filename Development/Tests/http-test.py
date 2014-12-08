#!/usr/bin/env python3

import http.client

try:
    connection = http.client.HTTPConnection('127.0.0.1:8080', timeout=10)
    connection.request('GET', "/ardukeyotp/1.0/verify")
    response = connection.getresponse()
    print(response.status, response.reason)

    data = response.read()
    print(data)

except:
    print('Error')
