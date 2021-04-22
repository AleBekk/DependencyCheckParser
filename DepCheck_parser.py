# OWASP Dependency Checker JSON Output Parsing & Sorting Script
#
# python DepChecker_parser.py -i DepChecker_output_SAMPLE.json
#
# required argument:
#   --input INPUT, -i INPUT     Path to input OWASP Dependency Checker JSON file to parse.
# optional arguments:
#   -h, --help                  Show this help message and exit
#   --filter, -f                Filter and sort
#   --summary, -s               Provide findings summary

import json
import argparse
import os
import sys


# Define argument parser
def create_arg_parser():
    parser = argparse.ArgumentParser(description='OWASP Dependency Checker JSON Output Parsing & Sorting Script')
    parser.add_argument('--filter', '-f', action="store_true",
                        help='Filter and sort')
    parser.add_argument('--summary', '-s', action="store_true",
                        help='Provide findings summary')
    parser.add_argument('--input', '-i', type=str, required=True,
                        help='Path to input OWASP Dependency Checker JSON file to parse.')
    return parser


# Create parser and check files exists
arg_parser = create_arg_parser()
parsed_args = arg_parser.parse_args(sys.argv[1:])
if os.path.exists(parsed_args.input):
    print('\nInput file: ' + parsed_args.input)
    inputF = parsed_args.input
    f = parsed_args.filter
    s = parsed_args.summary
    currentDir = os.getcwd()
    if f and s:
        flag = 0
        outputF = (currentDir + '/OWASP_Parsed_output.json')
        outputS = (currentDir + '/OWASP_Summary_output.json')
        output_file = open(outputF, 'w')
        output_fileS = open(outputS, 'w')
        print('Output files:\n' + outputF + '\n' + outputS + '\n')
    elif f:
        flag = 1
        outputF = (currentDir + '/OWASP_Parsed_output.json')
        output_file = open(outputF, 'w')
        print('Output file:\n' + outputF + '\n')
    elif s:
        flag = 2
        outputS = (currentDir + '/OWASP_Summary_output.json')
        output_fileS = open(outputS, 'w')
        print('Output file:\n' + outputS + '\n')
    else:
        flag = 3
        outputF = (currentDir + '/OWASP_Parsed_output.json')
        output_file = open(outputF, 'w')
        print('\nNo flags used, output will be filtered & sorted by default\n')
        print('Output file:\n' + outputF + '\n')
else:
    arg_parser.print_help(sys.stderr)
    print('\n\nERROR - Input file does not exist, exiting...\n')
    sys.exit(1)

# Define & load JSON input/output files
input_file = open(inputF)
json_decode = json.load(input_file)
dep_dict = (json_decode['dependencies'])

count = 0
result = []
summary = []


# Sorting and counting
def add_to_list(original_list, severity_name, new_list, filter):
    count = 0
    i = 0
    while i < len(result):
        obj = result.__getitem__(i)
        sev = obj.get('severity').upper()
        if filter:
            if sev == severity_name:
                count = count + 1
                new_list.append(obj)
                original_list.remove(obj)
            else:
                i += 1
        else:
            i += 1
            count = count + 1
            new_list.append(obj)
            original_list.remove(obj)
    print('found ' + str(count) + ' ' + severity_name + ' vulnerabilities')
    hist_o = {'severity': severity_name, 'vulnerabilities_number': count}
    summary.append(hist_o)


# Check if vulnerability name already exists
def exists(result, vuln_name):
    index = 0
    for item in result:
        if item.get('vulnerabilities_name') == vuln_name:
            return index
        index = index + 1
    return 0


# Filtering & extracting relevant data
for item in dep_dict:
    if item.get('vulnerabilities'):
        for vuln in item.get('vulnerabilities'):
            count = count + 1
            vuln_o = {'vulnerabilities_name': vuln.get('name'), 'severity': vuln.get('severity'),
                      'file_names': [item['fileName']]}
            index = exists(result, vuln.get('name'))
            if index > 0:
                result[index]['file_names'] = result[index]['file_names'] + vuln_o['file_names']
            else:
                result.append(vuln_o)
print('TOTAL: ' + str(len(result)) + ' vulnerabilities found\n')

# Sorting vulnerabilities by risk level
sorted_result = []
add_to_list(result, 'CRITICAL', sorted_result, True)
add_to_list(result, 'HIGH', sorted_result, True)
add_to_list(result, 'MEDIUM', sorted_result, True)
add_to_list(result, 'LOW', sorted_result, True)
add_to_list(result, 'UNKNOWN', sorted_result, False)

for obj in result:
    print(obj.get('severity'))

# Write to output json files
if flag == 0:
    print('\n------- Sorting & Filtering output -------\n')
    print(sorted_result)
    print('\n------- Summary output -------\n')
    print(summary)
    print('\n')
    output_json = json.dumps(sorted_result)
    output_file.write(output_json)
    output_file.close()
    output_json = json.dumps(summary)
    output_fileS.write(output_json)
    output_fileS.close()
elif flag == 2:
    print('\n------- Summary output -------\n')
    print(summary)
    print('\n')
    output_json = json.dumps(summary)
    output_fileS.write(output_json)
    output_fileS.close()
else:
    print('\n------- Sorting & Filtering output -------\n')
    print(sorted_result)
    print('\n')
    output_json = json.dumps(sorted_result)
    output_file.write(output_json)
    output_file.close()
