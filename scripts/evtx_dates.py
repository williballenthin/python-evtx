#!/usr/bin/env python

from lxml import etree
from datetime import datetime

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view

def get_child(node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
    return node.find("%s%s" % (ns, tag))

def to_lxml(record_xml):
	return etree.fromstring("<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\" ?>%s" % record_xml.encode('utf-8'))

def xml_records(filename):
	with Evtx(filename) as evtx:
		for xml, record in evtx_file_xml_view(evtx.get_file_header()):
			try:
				yield to_lxml(xml), None
			except etree.XMLSyntaxError as e:
				yield xml, e

def parsed_date(dstr):
	ts = None
	try:
		ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S')
	except ValueError:
		ts = datetime.strptime(dstr, '%Y-%m-%d %H:%M:%S.%f')
	return ts

def event_in_daterange(d, start, end):
	is_in_range = True
	if d < start:
		is_in_range = False
	if d > end:
		is_in_range = False
	return is_in_range

def matching_records(evtfile, sdatetime, edatetime):
	for node, err in xml_records(evtfile):
		if err is not None:
			continue
		else:
			sys = get_child(node, "System")
			t = parsed_date(get_child(sys, "TimeCreated").get("SystemTime"))
			if event_in_daterange(t, sdatetime, edatetime):
				yield node

def main():
	import argparse
	parser = argparse.ArgumentParser()
	parser.add_argument("evtfile", type=str)
	parser.add_argument("start", type=parsed_date, help="Start date/time YYYY-mm-dd HH:MM:SS(.f)")
	parser.add_argument("-e", dest="end", type=parsed_date, help="End date/time YYYY-mm-dd HH:MM:SS(.f)",
						default=datetime.now())
	args = parser.parse_args()
	
	for record in matching_records(args.evtfile, args.start, args.end):
		print(etree.tostring(record, pretty_print=True))
	
		
if __name__ == "__main__":
	main()
