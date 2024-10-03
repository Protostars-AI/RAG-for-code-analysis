#!/usr/bin/python
import sys
import logging

# Set up logging
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

# Import and run the Flask app
from init import app

if __name__== "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
