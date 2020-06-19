# Command line tool using the [GORACLER] lib

This cli is an example of using the goracler library
that performs padding oracle attacks.
The cli takes as input a config file and a http request
aspects of oracle to query:
- The base url of the oracle.
- The conditions to consider the http response a padding error or a non padding
  error.
