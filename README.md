# ASN1spect
This is the repository for the ASN1spect tool, which is designed to analyze ASN.1 type constraints from asn1c's generated code.

## Code
The main code for ASN1spect is available in python/ASN1spect, which contains a subfolder "Analysis" and each file represents an analysis module.

The GitHub study is contained in the GitHub_Study folder, which contains all the code to identify, clone and build repositories on GitHub with ASN.1 compilers.

ASN1spect can be installed with pip by running pypy3 -m pip install ./ in the python folder. This will install two commands: ASN1spect and GitHub_Study.

## Data
The data used in our paper is mostly available at the GitHub_Study/data/asn1c_repos.csv file. THis file contains all repositories we analyzed and specifications we identified.
