"""Holds the session header and other global variables."""
import sys
import os

from requests import Session

# Keeps track on if the user is logged in or not.
logged_in = dict()
logged_in['logged_in'] = False
logged_in['publicKey'] = None
logged_in['privateKey'] = None
logged_in['apiKey'] = None


# The session object for making get and post requests.
SESSION = Session()
SESSION.headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip,deflate,br",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    "X-Robinhood-API-Version": "1.431.4",
    "Connection": "keep-alive",
    'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15'
}

#All print() statement direct their output to this stream
#by default, we use stdout which is the existing behavior
#but a client can change to any normal Python stream that
#print() accepts.  Common options are
#sys.stderr for standard error
#open(os.devnull,"w") for dev null
#io.StringIO() to go to a string for the client to inspect
OUTPUT=sys.stdout
