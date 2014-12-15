import http.client
import json
import sys
import hmac, hashlib

server = '127.0.0.1:8080'
requestTimeout = 3000
print(server)


class BadHmacSignatureError(Exception):
    """
    Dummy exception for wrong HMAC.

    """
    pass


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
connection.request('GET', '/ardukeyotp/1.0/verify?otp='+ request['otp'] +'&nonce='+ request['nonce'] +'&apiId='+ str(request['apiId']) +'&hmac='+ request['hmac'])

httpResponse = connection.getresponse()
httpResponseData = httpResponse.read().decode()

try:
    ## Convert JSON response to Python dict
    httpResponse = json.loads(httpResponseData)

    ## Save the HMAC
    responseHmac = httpResponse['hmac']

    ## Exclude response HMAC itself from HMAC calculation
    httpResponse['hmac'] = ''

    calculatedResponeHmac = __calculateHmac(httpResponse)

    ## Check if calculated HMAC matches received
    if ( responseHmac != calculatedResponeHmac ):
        raise BadHmacSignatureError('The response HMAC is not valid!')

    ## Retrieve response data
    responseOtp = httpResponse['otp']
    responseNonce = httpResponse['nonce']
    responseStatus = httpResponse['status']
    responseTime = httpResponse['time']

except BadHmacSignatureError as e:
    print(e)

except KeyError:
    print('Error while parsing HTTP response!')

except:
    print('Unknown error occured: '+ str(sys.exc_info()[1]))

print(httpResponseData)
