import requests
import json
import urllib3
import argparse
import sys

if sys.version_info < (3, 5):
    print('Please upgrade your Python version to 3.5 or higher')
    sys.exit(1)

def export_awaf_policies(device,username,password,format,output):

    if not(format == "xml" or format == "json" or format == "plc"):
        print("ERROR: invalid format specified", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    session.verify=False
    session.auth = (username,password)
  
    #get all awaf policies
    try:
        req = session.get("https://%s/mgmt/tm/asm/policies?$select=name,id,fullPath,link" % device)
        req.raise_for_status()
    except requests.exceptions.RequestException as error:
        print("ERROR: %s" % error, file=sys.stderr)
        sys.exit(1)

    awaf_policies = req.json()['items']

    for policy in awaf_policies:

        filename = policy['fullPath'][1:].replace("/","-") + "." + format

        data = {}
        data['filename'] = filename

        if format == "plc":
            data['format'] = "binary"
        else:
            data['format'] = format

        data['policyReference'] = {}
        data['policyReference']['link'] = policy['selfLink']

        #export awaf policy
        try:
            req = session.post("https://%s/mgmt/tm/asm/tasks/export-policy" % device, json=data)
            req.raise_for_status()
        except requests.exceptions.RequestException as error:
            print("ERROR: %s" % error, file=sys.stderr)
            sys.exit(1)

        task_link = req.json()['selfLink'].replace("localhost",device)

        # wait for the export task finished
        while True:
            try:
                req = session.get(task_link)
                req.raise_for_status()
            except requests.exceptions.RequestException as error:
                print("ERROR: %s" % error, file=sys.stderr)
                sys.exit(1)

            task_status = req.json()['status']

            if task_status == "COMPLETED":
                # task_message = req.json()['status']['message']
                task_message = task_status
                # chunk_size = req.json()['result']['fileSize']
                # if chunk_size > 512 * 1024:
                #     chunk_size = 512 * 1024
                break

        # if the policy was successfully exported, download and save the file
        if "COMPLETED" in task_message:

            filepath = "%s/%s" % (output,filename)

            if format == "json" or format == "xml":
                exportedPolicy = open(filepath, "w")
            else:
                exportedPolicy = open(filepath, "wb")

            ##
            ## This where I need to loop around for the full file size, the chunking to capture the whole download
            ##

            chunk_size = 512 * 1024
            start = 0
            end = chunk_size - 1
            size = 0
            current_bytes = 0

            while True:
                content_range = "%s-%s/%s" % (start, end, size)
                headers = {
                    # 'Content-Range': content_range,
                    'Range': content_range,
                    'Content-Type': 'application/octet-stream'
                    # 'Content-Type': 'application/json'
                }
                data = {
                    'headers': headers,
                    'verify': False,
                    'stream': True
                }

                try:
                    response = session.get("https://%s/mgmt/tm/asm/file-transfer/downloads/%s" % (device,filename), headers=headers, data=data)
                    response.raise_for_status()
                except requests.exceptions.RequestException as error:
                    print("ERROR: %s" % error, file=sys.stderr)
                    sys.exit(1)

                if response.status_code == 200:
                    # If the size is zero, then this is the first time through
                    # the loop and we don't want to write data because we
                    # haven't yet figured out the total size of the file.
                    if size > 0:
                        current_bytes += chunk_size
                        for chunk in response.iter_content(chunk_size):
                            exportedPolicy.write(str(chunk))
                # Once we've downloaded the entire file, we can break out of
                # the loop
                if end == size:
                    break
                # crange = response.headers['Content-Range']
                crange = response.headers['Content-Length']
                # Determine the total number of bytes to read.
                if size == 0:
                    size = int(crange.split('/')[-1]) - 1
                    # If the file is smaller than the chunk_size, the BigIP
                    # will return an HTTP 400. Adjust the chunk_size down to
                    # the total file size...
                    if chunk_size > size:
                        end = size
                    # ...and pass on the rest of the code.
                    continue
                start += chunk_size
                if (current_bytes + chunk_size) > size:
                    end = size
                else:
                    end = start + chunk_size - 1

            exportedPolicy.close()

            print("AWAF Policy %s saved to file %s." % (policy["fullPath"], filepath))
        else:
            print("ERROR: failed to export AWAF Policy %s" % policy["fullPath"], file=sys.stderr)           

def main():
    
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description = 'A small script to export all AWAF policies from a BIG-IP device.')

    parser.add_argument('--device', '-d', type=str, required=True)
    parser.add_argument('--username', '-u', type=str, required=True)
    parser.add_argument('--password', '-p', type=str, required=True)
    parser.add_argument('--format', '-f', type=str, required=False, default="xml", choices=['json','xml','plc'])
    parser.add_argument('--output', '-o', type=str, required=False, default=".")

    # lab
    src_bigip_host = "test01.my.corp"
    user_name = ""
    password = ""
    format = "xml"
    input = "./asm-policy-import/policiesLab" 

    export_awaf_policies(src_bigip_host,user_name,password,format,input)

    # args = parser.parse_args()

    # export_awaf_policies(args.device,args.username,args.password,args.format,args.output)

if __name__ == "__main__":
   main()
