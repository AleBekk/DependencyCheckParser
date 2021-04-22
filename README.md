# dependencyCheckerParser

Python script to filter and sort the OWASP Dependency Checker JSON output. 

# Example:

# python DepChecker_parser.py -i DepChecker_output_SAMPLE.json

# required argument:
#   --input INPUT, -i INPUT     Path to input OWASP Dependency Checker JSON file to parse.
# optional arguments:
#   -h, --help                  Show this help message and exit
#   --filter, -f                Filter and sort
#   --summary, -s               Provide findings summary


The JSON data is filtered (vulnerability name, severity and file names) and sorted by severity.

A sample of the filtered and sorted JSON output is represented below.

```
[
  {
    "vulnerabilities_name" : "CVE-2018-16492",
    "severity" : "CRITICAL",
    "file_names" : [
      "deep-extend:0.6.0",
      "extend-shallow:2.0.1",
      "static-extend:0.1.2"
    ]
  },
  {
    "vulnerabilities_name" : "CVE-2020-8116",
    "severity" : "CRITICAL",
    "file_names" : [
      "dot-prop:4.2.0"
    ]
  },
  ...
]
```

In addition, the script has the fuctionality to number the vulnerabilities by severity.

An example of the output for this is represented below

```
[
  {
    "severity": "CRITICAL",
    "num_vulnerabilities": 3
  }, 
  {
    "severity": "HIGH",
    "num_vulnerabilities": 12
  }, 
  {
    "severity": "MEDIUM",
    "num_vulnerabilities": 9
  },
  ...
]
```
