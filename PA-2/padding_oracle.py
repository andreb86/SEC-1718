import sys
import urllib.request
import urllib.error
import urllib.parse

TARGET = 'http://crypto-class.appspot.com/po?er='


class PaddingOracle(object):

    """
    Object Oriented implementation of the padding oracle attack
    """

    def __init__(self):

        # Init the instance variables.
        good_padding = False


    def query(self, q):
        target = TARGET + urllib.request.quote(q)  # Create query URL
        req = urllib.request.Request(target)  # Send HTTP request to server
        try:
            f = urllib.request.urlopen(req)  # Wait for response
        except urllib.error.HTTPError as e:
            print(f"We got: {e.code:d}")  # Print response code
            if e.code == 404:
                return True  # good padding
            return False  # bad padding


if __name__ == "__main__":
    po = PaddingOracle()
    po.query(sys.argv[1])  # Issue HTTP query with the given argument
