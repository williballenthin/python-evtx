#!/usr/bin/env python

import setuptools

long_description="""python-evtx is a pure Python parser for recent Windows Event Log files (those with the file extension ".evtx"). The module provides programmatic access to the File and Chunk headers, record templates, and event entries. For example, you can use python-evtx to review the event logs of Windows 7 systems from a Mac or Linux workstation. The structure definitions and parsing strategies were heavily inspired by the work of Andreas Schuster and his Perl implementation "Parse-Evtx"."""

setuptools.setup(name="python-evtx",
      version="0.5.3",
      description="Pure Python parser for recent Windows event log files (.evtx).",
      long_description=long_description,
      author="Willi Ballenthin",
      author_email="willi.ballenthin@gmail.com",
      url="https://github.com/williballenthin/python-evtx",
      license="Apache 2.0 License",
      packages=setuptools.find_packages(),
      install_requires=['hexdump', 'six'],
      scripts = ['scripts/evtx_dump',
                 'scripts/evtx_dump_chunk_slack',
                 'scripts/evtx_eid_record_numbers',
                 'scripts/evtx_extract_record',
                 'scripts/evtx_filter_records',
                 'scripts/evtx_find_bugs',
                 'scripts/evtx_get_pretty_record',
                 'scripts/evtx_info',
                 'scripts/evtx_record_structure',
                 'scripts/evtx_structure',
                 'scripts/evtx_templates']
)
