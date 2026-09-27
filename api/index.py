"""
api/index.py
------------
Vercel's Python runtime looks for a WSGI/ASGI app here and routes all
incoming requests to it. This file just imports the real Flask app that
lives in app.py at the project root and exposes it as `app`, which is
what Vercel expects.

You don't need to run this file yourself - it's only used by Vercel.
"""

import os
import sys

# Make sure Python can find app.py / detector.py in the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app  # noqa: E402  (Vercel's Python runtime expects `app` here)
