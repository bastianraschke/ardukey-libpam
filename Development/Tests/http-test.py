import http.client
import json
import hmac, hashlib

server = '127.0.0.1:8080'
requestTimeout = 3000
print(server)

def __calculateHmac(data):
    """
    Calculates a hexadecimal Hmac of given data dictionary.

    @param dict data
    The dictionary that contains data.

    @return string
    """

    __sharedSecret = 'abc'

    ## Only process dictionaries
    if ( type(data) != dict ):
        raise ValueError('The given data is not a dictionary!')

    ## Checks if shared secret is given
    if ( len(__sharedSecret) == 0 ):
        raise ValueError('No shared secret given!')

    payloadData = ''

    ## Sort dictionary by key, to calculate the same Hmac always
    for k in sorted(data):
        payloadData += data[k]

    sharedSecret = __sharedSecret.encode('utf-8')
    payloadData = payloadData.encode('utf-8')

    ## Calculate HMAC of current response
    return hmac.new(sharedSecret, msg=payloadData, digestmod=hashlib.sha256).hexdigest()

## Set up request
request = {}
request['otp'] = 'cccccccccccbefrkinfgvbhvbhttjtbdkkitffhjighh'
request['nonce'] = 'YH3E3JDN7GMWX6XGA2VQ0LZDLZ3BFFG1'
request['apiId'] = '1000'
request['hmac'] = __calculateHmac(request)

## TODO: Check timeout issue
connection = http.client.HTTPConnection(server, timeout=requestTimeout)
#headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
connection.request('GET', '/ardukeyotp/1.0/verify?otp='+ request['otp'] +'&nonce='+ request['nonce'] +'&apiId='+ str(request['apiId']) +'&hmac='+ request['hmac'])
#connection.request('GET', '/ardukeyotp/1.0/verify', request, headers)

httpResponse = connection.getresponse()
httpResponseData = httpResponse.read().decode()
print(httpResponseData)
