#!/usr/bin/env python

from Evtx import __version__
from setuptools import setup

setup(name="python-evtx",
      version=__version__,
      description="Pure Python parser for recent Windows event log files (.evtx).",
      author="Willi Ballenthin",
      author_email="willi.ballenthin@gmail.com",
      url="https://github.com/williballenthin/python-evtx",
      license="Apache 2.0 License",
      packages=["Evtx"])
