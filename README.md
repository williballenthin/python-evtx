python-evtx
===========

Introduction
------------

python-evtx is a pure Python parser for recent Windows Event Log files (those with the file extension ".evtx").  The module provides programmatic access to the File and Chunk headers, record templates, and event entries.  For example, you can use python-evtx to review the event logs of Windows 7 systems from a Mac or Linux workstation. The structure definitions and parsing strategies were heavily inspired by the work of Andreas Schuster and his Perl implementation "Parse-Evtx".

Background
----------
With the release of Windows Vista, Microsoft introduced an updated event log file format.  The format used in Windows XP was a circular buffer of record structures that each contained a list of strings.  A viewer resolved templates hosted in system library files and inserted the strings into appropriate positions.  The newer event log format is proprietary binary XML.  Unpacking chunks from an event log file from Windows 7 results in a complete XML document with a variable schema.  The changes helped Microsoft tune the file format to real-world uses of event logs, such as long running logs with hundreds of megabytes of data, and system independent template resolution.

Related Work
------------
Andreas Schuster released the first public description of the .evtx file format in 2007.  He is the author of the thorough document "Introducing the Microsoft Vista event log file format" that describes the motivation and details of the format.  Mr. Schuster also maintains the Perl implementation of a parser called "Parse-Evtx".  I referred to the source code of this library extensively during the development of python-evtx.

Joachim Metz also released a cross-platform, LGPL licensed C++ based parser in 2011.  His document "Windows XML Event Log (EVTX): Analysis of EVTX" provides a detailed description of the structures and context of newer event log files.

Dependencies
------------
python-evtx works on both the 2.7 and 3.x versions of the Python programming language. As it is purely Python, the module works equally well across platforms.  The code does not depend on any modules that require separate compilation; however, if you have lxml installed, its even nicer.

python-evtx operates on event log files from Windows operating systems newer than Windows Vista.  These files typically have the file extension .evtx.  Version 5.09 of the `file` utility identifies such a file as "MS Vista Windows Event Log".  To manual confirm the file type, look for the ASCII string "ElfFile" in the first seven bytes:

    willi/evtx  » xxd -l 32 Security.evtx 
    0000000: 456c 6646 696c 6500 0000 0000 0000 0000  ElfFile.........
    0000010: d300 0000 0000 0000 375e 0000 0000 0000  ........7^......


Examples
--------
Provided with the parsing module `Evtx` are three scripts that mimic the tools distributed with Parse-Evtx.  `evtxinfo.py` prints metadata about the event log and verifies the checksums of each chunk.  `evtxtemplates.py` builds and prints the templates used throughout the event log.  Finally, `evtxdump.py` parses the event log and transforms the binary XML into a human readable ASCII XML format.

Note the length of the `evtxdump.py` script: its only 20 lines.  Now, review the contents and notice the complete implementation of the logic:

    print(e_views.XML_HEADER)
    print('<Events>')
    for record in log.records:
        print(record.xml())
    print('</Events>')  

Working with python-evtx is really easy!


Installation
------------
Updates to python-evtx are pushed to PyPi, so you can install the module using either `easy_install` or `pip`.  For example, you can use `pip` like so:

    pip install python-evtx

The source code for python-evtx is hosted at Github, and you may download, fork, and review it from this repository (http://www.github.com/williballenthin/python-evtx).  Please report issues or feature requests through Github's bug tracker associated with the project.

License
-------
python-evtx is licensed under the Apache License, Version 2.0.  This means it is freely available for use and modification in a personal and professional capacity.  

