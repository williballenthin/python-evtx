#!/usr/bin/env python

import setuptools

long_description = """python-evtx is a pure Python parser for \
Windows Event Log files (those with the file extension ".evtx"). \
The module provides programmatic access to the File and Chunk headers, \
record templates, and event entries. For example, you can use \
python-evtx to review the event logs of Windows 7 systems from \
a Mac or Linux workstation. The structure definitions and parsing \
strategies were heavily inspired by the work of Andreas Schuster \
and his Perl implementation "Parse-Evtx"."""

setuptools.setup(
        name="python-evtx",
        version="0.8.0",
        description="Pure Python parser for recent Windows event log files (.evtx).",
        long_description=long_description,
        author="Willi Ballenthin",
        author_email="willi.ballenthin@gmail.com",
        url="https://github.com/williballenthin/python-evtx",
        license="Apache 2.0 License",
        packages=setuptools.find_packages(),
        python_requires='>=3.8',
        install_requires=[
            'hexdump>=3.3',
            ],
        extras_require={
            "test": [
                'pytest-cov==5.0.0',
                'pytest==8.2.2',
                'lxml==5.2.2',
                'black==24.4.2',
                'isort==5.13.2',
                'ruff==0.4.10',
            ]
        },
        scripts=['scripts/evtx_dump.py',
                 'scripts/evtx_dump_json.py',
                 'scripts/evtx_dump_chunk_slack.py',
                 'scripts/evtx_eid_record_numbers.py',
                 'scripts/evtx_extract_record.py',
                 'scripts/evtx_filter_records.py',
                 'scripts/evtx_info.py',
                 'scripts/evtx_record_structure.py',
                 'scripts/evtx_structure.py',
                 'scripts/evtx_templates.py',
                 ],
)
