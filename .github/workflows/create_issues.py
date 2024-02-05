#!/bin/python3

import sys
import json
import requests
from time import sleep
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

######################################################################################
# create_issues.py
#
#   Description:
#	This script will take the output of the Snyk Test command in json format.
#	This output will be a collection of vulnerabilities.  For each vulnerability,
#	an issue will be created in Github.  If no vulnerabilities are found, an 
#	issue will still be created specifying that no vulnerabilities were detected.
#
######################################################################################



#
# parse_arguments
#   Input: raw_args - arguments from the commandline
#
#   Description:
#	Specifies the expected commandline arguments and makes sure all required
#	arguments are included
#
def parse_arguments(raw_args):
    parser = ArgumentParser(description='Reads the results of a Snyk test and creates github issues',
                            formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument('-f', '--file',          type=str,     help='json file to read')
    parser.add_argument('-r', '--repo',          type=str,     help='Github repo name in format "owner/repo"')
    parser.add_argument('-t', '--token',         type=str,     help='Github auth token')
    args = parser.parse_args(raw_args)

    if not args.file:
        print ("Error: Snyk test results file not specified.  Please include -f <filename> argument")
        sys.exit(1)
    if not args.repo:
        print ("Error: Github repo not specified.  Please include -r <repo name> argument")
        sys.exit(1)
    if not args.token:
        print ("Error: Github token not specified.  Please include -t <token> argument")
        sys.exit(1)

    return args



#
# submit_issue
#   Input: 
#	vuln - json formatted vulnerability object as reported by Snyk Test
#
#   Description: 
#	Makes a Github API call to create an issue for the given vulnerability
#	If 'vuln' is None, it still creates an issue, but the issue just states 
#	that no vulnerabilities were found
#
def submit_issue(vuln):
		
    if vuln:
        try:
            print ("")
            print ("Vulnerability:")
            print ("ID: %s" % vuln['id'])
            print ("Title: %s" % vuln['title'])
            print ("Package Name: %s" % vuln['packageName'])
            print ("Package Version: %s" % vuln['version'])
            print ("")
        except:
            print ("Error: Vulnerability report is missing required data, it needs title, body, packageName and version")
            return

        data = {"title": "Snyk: Vulnerability Found: %s" % vuln['title'],
	    "body":	"""Title: %s
ID: %s
Package Name: %s
Package Version: %s""" % (vuln['title'], vuln['id'], vuln['packageName'], vuln['version'])}
    else:
        data = {"title": "Snyk: No Security Issues Found"}

    url = "https://api.github.com/repos/%s/issues" % args.repo
    headers = {"Authorization": "Bearer %s" % args.token}
    print ("Making requests call to %s" % url)

    try:
        r = requests.post(url=url, headers=headers, json=data)
        res = r.json()
        if r.status_code >= 200 and r.status_code < 300:
            print("Issue created successfully: Status %s" % r.status_code)
        else:
            print("Error: Issue creation failure.  Status %s" % r.status_code)
        #print (res)
        sleep(1)
    except:
        print("Error: Request timed out or failed: Status %s" % r.status_code)



#####################
####### MAIN ########
#####################

raw_args = sys.argv[1:]
args = parse_arguments(raw_args)

f = open(args.file)
res_txt = f.read()
#print (res_txt)
res_json = json.loads(res_txt)

if len(res_json) == 0:
    # No critical vulnerabilities found
    submit_issue(None)
else:
    for res in res_json['vulnerabilities']:
        submit_issue(res)
