# Written by AJ Read with help from evtx_dump.py file. Adds functionality to dump EVTX to JSON.

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

        # If output is desired
        if (args.output):
            # Output the JSON data
            if (os.path.splitext(args.output)[1] == ".json"): #if the file extension is correct
                json_file=args.output
            else: # if the file extension is incorrect
                json_file=args.output +".json"
            with open(json_file,"w") as outfile: #write to an output file
                json.dump(final_json,outfile)
        else:
            print(final_json)
if __name__ == "__main__":
    main()
