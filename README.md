npm package to keep an eye on the expiry dates of your SSL certificates
=======================================================================

This script connects to a given set of servers, fetches and verifies their
SSL certificates, and checks the expiry dates etc. It will warn you if:

  * the connection does not succeed,
  * the SSL negotiation does not succeed,
  * the SSL certificate does not verify,
  * the SSL certificate does not match the server hostname,
  * the server does not support SSL,
  * the certificate uses MD5 or SHA1,
  * the certificate has expired,
  * the certificate was issued on 1st March 2018 or later
    and is valid for over [825 days](https://cabforum.org/2017/03/17/ballot-193-825-day-certificate-lifetimes/),
  * the certificate was issued by Symantec, Thawte, RapidSSL or Geotrust
    and the [Chrome distrust date](https://security.googleblog.com/2017/09/chromes-plan-to-distrust-symantec.html) is soon,
  * or the certificate will expire soon.

The intended use is that you will put the list of your servers using
SSL in a text file, and run `sslexpiry` on a daily cron job to warn
you if your certificates will expire soon.


Requirements
------------

The script relies on node 8 (it has been tested under node 8.9.4).
You can install it with:

    sudo npm install -g sslexpiry


Usage
-----

    usage: sslexpiry [-h] [-d DAYS] [-f FILENAME] [-t SECONDS] [-v] [-V]
                     [SERVER [SERVER ...]]

    SSL expiry checker

    Positional arguments:
      SERVER                Check the specified server.

    Optional arguments:
      -h, --help            Show this help message and exit.
      -d DAYS, --days DAYS  The number of days at which to warn of expiry.
                            (default=30)
      -f FILENAME, --from-file FILENAME
                            Read the servers to check from the specified file.
      -t SECONDS, --timeout SECONDS
                            The number of seconds to allow for server response.
                            (default=30)
      -v, --verbose         Display verbose output.
      -V, --version         Show program's version number and exit.


Files containing lists of servers can contain blank lines, and any
characters from a '#' onwards are ignored as comments.

Servers specified in the files or on the command line are of the form:

    hostname[:port][/protocol]

`port` can be a number or a standard service name (e.g. 'https'). If it
is omitted then 'https' is assumed.

`protocol` specifies a protocol that should be followed before the SSL
negotiation begins. Valid values include `smtp`, `imap` or `none`. If
it is omitted then `none` is assumed, except for ports `smtp` or
`submission`, where `smtp` is assumed, and `imap`, where `imap` is
assumed.

If the `-v` option is specified, then output will be shown with any problems
found first, then all tested servers listed with soonest expiry date first.

The process exit code will be zero if no problems were found, and
non-zero otherwise.


Example server list file
------------------------

    # This is an example server list file

    www.example.com
    example.com
    mail.example.com:smtp
    othermail.example.com:2525/smtp # this server listens for smtp on port 2525


Example output
--------------

    $ sslexpiry -vf example.conf
    example.com                     Hostname/IP doesn't match certificate's altnames
    www.example.com                 Certificate expiry date is 13 Mar 2018 - 6 days
    othermail.example.com:2525/smtp 03 Jul 2018
    mail.example.com:smtp           10 Oct 2018


History
-------

### 1.3.0 (2018-03-18)

    - Add tests and Travis integration
    - Miscellaneous fixes found by the tests

### 1.2.0 (2018-03-12)

    - Fix argument parsing by replacing commander with argparse

### 1.1.0 (2018-03-08)

    - Check certificate is not using MD5 or SHA1

### 1.0.0 (2018-03-07)

    - Initial release.
