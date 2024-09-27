#!/usr/bin/python
import sys
import logging

# Set up logging
logging.basicConfig(stream=sys.stderr, level=logging.INFO)

# Import and run the Flask app
from init import app

if __name__== "__main__":
    app.run(debug=True)
