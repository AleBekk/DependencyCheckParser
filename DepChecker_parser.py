# OWASP output parsing script - CVEs filtering and sorting

import json

# Define & load JSON input/output files
input_file = open('/OWAS_DepChecker_report.json', 'r')
output_file_ex2 = open('/Filter-Sort_output.json', 'w')
output_file_ex3 = open('/Histogram_output.json', 'w')
json_decode = json.load(input_file)
dep_dict = (json_decode['dependencies'])

count = 0
result = []
histogram = []


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
    hist_o = {'severity': severity_name, 'num_vulnerabilities': count}
    histogram.append(hist_o)


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
print('TOTAL: ' + str(len(result)) + ' vulnerabilities found')

# Sorting CVEs by risk level
sorted_result = []
add_to_list(result, 'CRITICAL', sorted_result, True)
add_to_list(result, 'HIGH', sorted_result, True)
add_to_list(result, 'MEDIUM', sorted_result, True)
add_to_list(result, 'LOW', sorted_result, True)
add_to_list(result, 'UNKNOWN', sorted_result, False)

for obj in result:
    print(obj.get('severity'))

# Write to output json files
output_json = json.dumps(sorted_result)
output_file_ex2.write(output_json)
output_file_ex2.close()

output_json = json.dumps(histogram)
output_file_ex3.write(output_json)
output_file_ex3.close()

print('------- Sorting & Filtering output: -------')
print(sorted_result)
print('------- Histogram output: -------')
print(histogram)
