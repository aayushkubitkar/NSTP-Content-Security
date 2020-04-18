# NSTP Client Reference Implementation

Contained herein is a reference client implementation of a subset of NSTPv4, which supports certificate-based mutual authentication of clients and servers.  This can (optionally) be used as a basis for building a solution to the NSTP content security assignment.

# NSTP Client Quickstart

Ensure that you have a working python3 installation.  Then, create and activate a virtual environment:

~~~sh
$ python3 -m venv venv
$ source ./venv/bin/activate
~~~

Install the module and prerequisites into your local environment:

~~~sh
$ pip install --editable .
~~~

You should now be able to run the entry point locally:

~~~sh
$ nstpc --help
Usage: nstpc [OPTIONS]

Options:
  -c, --client-certificate TEXT   [required]
  -d, --debug
  -k, --key TEXT                  [required]
  -p, --client-private-key TEXT   [required]
  -s, --server-address TEXT       [required]
  -t, --trust-store TEXT          [required]
  -v, --status-server-address TEXT
                                  [required]
  --help                          Show this message and exit.
~~~

Modifications to source files will also be immediately picked up without requiring a reinstallation of the module.
