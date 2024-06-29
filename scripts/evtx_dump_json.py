#!/usr/bin/env python3
#   This file is part of python-evtx.
#   Written by AJ Read (ajread4) with help/inspiration from the evtx_dump.py file written by Willi Ballenthin.
#
#   Purpose: User can dump evtx data into JSON format to either the command line or a JSON file in new line delimited format/JSON array.
#   Details: The JSON object is created with only the EventRecordID from the System section of the evtx XML and all of the information within the EventData section.

import Evtx.Evtx as evtx
import Evtx.Views as e_views

# Added packages
import os
import xmltodict
import json


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Dump a binary EVTX file into XML.")
    parser.add_argument("evtx", type=str,action='store',
                        help="Path to the Windows EVTX event log file")
    parser.add_argument("-o","--output",type=str, action='store',
                        help="Path of output JSON file")
    args = parser.parse_args()

    with evtx.Evtx(args.evtx) as log:

        # Instantiate the final json object
        final_json=[]

        # Loop through each record in the evtx log
        for record in log.records():

            # Convert the record to a dictionary for ease of parsing
            data_dict=xmltodict.parse(record.xml())

            # Create first line of System Data based on the EventRecordID
            json_subline={}
            json_subline.update({'EventRecordID':data_dict['Event']['System']['EventRecordID']})


            # Loop through each key,value pair of the System section of the evtx logs
            for event_system_key, event_system_value in data_dict['Event']['System'].items():

                if not (event_system_key=="EventRecordID") or not (event_system_key=="Execution"):

                    # For nested dictionaries, loop through each and extract key information 
                    if isinstance(event_system_value,dict):
                        for event_system_subkey,event_system_subvalue in event_system_value.items():

                            if event_system_key=="EventID" or event_system_key=="TimeCreated":
                                json_subline.update({event_system_key: event_system_subvalue})
                            if event_system_key=="Security": 
                                json_subline.update({event_system_subkey[1:]: event_system_subvalue})

                    else: 
                        json_subline.update({event_system_key: event_system_value})

            # Loop through each key, value pair of the EventData section of the evtx logs
            if data_dict['Event']['EventData']!= None: 
                for event_data_key, event_data_value in data_dict['Event']['EventData'].items():
                    for values in event_data_value:

                        # Loop through each subvalue within the EvenData section to extract necessary information
                        for event_data_subkey,event_data_subvalue in values.items():
                            if event_data_subkey=="@Name":
                                data_name=event_data_subvalue
                            else:
                                data_value=event_data_subvalue

                                # Add information to the JSON object for this specific log
                                json_subline.update({data_name: data_value})
                                
            # Add specific log JSON object to the final JSON object
            if not final_json:
                final_json=[json_subline]
            else:
                final_json.append(json_subline)

        # If output is desired
        if (args.output):

            # Output the JSON data
            if (os.path.splitext(args.output)[1] == ".json"):
                json_file=args.output
            else:
                json_file=args.output +".json"

            # Write to JSON file
            with open(json_file,"w") as outfile:
                json.dump(final_json,outfile)
        else:
            print(json.dumps(final_json))

if __name__ == "__main__":
    main()
