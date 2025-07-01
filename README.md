# ServiceNow exporter and application builder for VCF Operations

## Introduction
This repository contains example code for how to query ServiceNow about relationships between servers and 
applications. This information is used to build Application resources in VCF Operations.

## Usage 
```text
usage: snow-exporter [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE]
                     --snowhost SNOWHOST --snowuser SNOWUSER --snowpassword
                     SNOWPASSWORD [-A] [-t TSFILE] [-U]

Exports relationships from ServiceNow and uses them to create applications in
VCF Ops

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The VCF Operations host
  -u USER, --user USER  The VCF Operations user
  -p PASSWORD, --password PASSWORD
                        The VCF Operations password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        The VCF Operations authentication source. Defaults to
                        local
  --snowhost SNOWHOST   The ServiceNow host
  --snowuser SNOWUSER   The ServiceNow user
  --snowpassword SNOWPASSWORD
                        The ServiceNow password
  -A, --all             Process all relationships even if not changed
  -t TSFILE, --tsfile TSFILE
                        Name of file storing latest timestamp. Default is
                        ~/.snow-exporter/
  -U, --unsafe          Skip SSL verification. This is not recommended in
                        production!
```