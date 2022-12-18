#!/usr/bin/env python
#    This file is part of python-evtx.
#
#   Copyright 2012, 2013 Willi Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#   Version v0.1.1
import Evtx.Evtx as evtx
import Evtx.Views as e_views
import os
import xmltodict
import json


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Dump a binary EVTX file into XML.")
    parser.add_argument("evtx", type=str,
                        help="Path to the Windows EVTX event log file")
    parser.add_argument("-o","--output",type=str,help="Path to output JSON file")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:

        if (args.output):
            final_json=[]
            for record in log.records():
                data_dict=xmltodict.parse(record.xml()) #convert the xml to a dictionary
                for event_system_key, event_system_value in data_dict['Event']['System'].items():  # loop through each key and value pair
                    if (event_system_key=="EventRecordID"):
                        json_subline={}
                        firstline={event_system_key:event_system_value}
                        json_subline.update(firstline) #add the event ID to JSON subline
                for event_data_key, event_data_value in data_dict['Event']['EventData'].items():  # loop through each key and value pair
                    for values in event_data_value:
                        for event_data_subkey,event_data_subvalue in values.items(): #loop through each
                            if event_data_subkey=="@Name": #extract the name from the value
                                data_name=event_data_subvalue
                            else:
                                data_value=event_data_subvalue #extract the true value
                        json_subline.update({data_name:data_value}) #update the JSON sub line
                final_json.append(json_subline) #update the final

            # Output the JSON data
            if (os.path.splitext(args.output)[1] == ".json"): #if the file extension is correct
                json_file=args.output
            else: # if the file extension is incorrect
                json_file=args.output +".json"
            with open(json_file,"w") as outfile: #write to an output file
                json.dump(final_json,outfile)
        else:
            print(e_views.XML_HEADER)
            print("<Events>")
            for record in log.records():
                print(record.xml())
            print("</Events>")


if __name__ == "__main__":
    main()
