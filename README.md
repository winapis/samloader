# samloader
1. Download firmware for Samsung devices (without any extra Windows drivers).
1. Supports Standard CSCs and EUX/EUY Regions
1. Updated to handle recent FUS Changes
1. Includes an IMEI Generator to satisfy FUS requests

## Installation
```
pip3 uninstall samloader (if previously installed)
pip3 install git+https://github.com/ananjaser1211/samloader.git
```

## Quick Usage and Notes
Run with `samloader` or `python3 -m samloader`. See `samloader --help` and `samloader (command) --help` for help.

1. IMEI/TAC and MODEL need to match otherwise downloads/decrypt wont be allowed.
1. Devices with No IMEI or devices that DONT accept IMEIs can use Serial Number instead with option -s
1. TAC Index is the first 8 Digits of the device IMEI
1. -i can be either a 15 Digit IMEI or 8 Digit TAC Index
1. when TAC Index is used, samloader will attempt to generate a valid fake IMEI and pass it to FUS
1. Its wise to store valid IMEIs in a list for later use, the generator will only perform 5 attempts per run
1. While its not perfect, this is in place to protect your own IMEIs incase samsung has other plans for us
1. download and decrypt functions support the IMEI/TAC Generator, Checkupdate does not require IMEI/TAC

`-m <model> -r <region> checkupdate`: Check the latest firmware version

`-m <model> -r <region> -i <IMEI or TAC> download (-O <output-dir> or -o <output-file>)`: Auto Download/Resume And Decrypt latest firmware version

`-m <model> -r <region> -i <IMEI or TAC> download --use-aria2c (-O <output-dir> or -o <output-file>)`: Download using aria2c for faster multi-connection downloads

`-m <model> -r <region> decrypt -v <version> -i <IMEI or TAC> -i <input-file> -o <output-file>`: Decrypt encrypted firmwares

### Example
```
$ samloader -m SM-F936B -r EUX checkupdate
F936BXXS4DWJ2/F936BOXM4DWH7/F936BXXS4DWJ2/F936BXXS4DWJ2
$ samloader -m SM-F936B -r EUX -i <IMEI/TAC> download -O .
downloading SM-F936B_2_20231031184951_xuh31ziqh0_fac.zip.enc4
$ samloader -m SM-F936B -r EUX -i <IMEI/TAC> download --use-aria2c -O .
Using aria2c for download...
$ samloader -m SM-F936B -r EUX -i <IMEI/TAC> decrypt -v F936BXXS4DWJ2/F936BOXM4DWH7/F936BXXS4DWJ2/F936BXXS4DWJ2 -i SM-F936B_2_20231031184951_xuh31ziqh0_fac.zip.enc4 -o SM-F936B_2_20231031184951_xuh31ziqh0_fac.zip
```

## Notes
This project was formerly hosted at `nlscc/samloader`, and has moved to `ananjaser1211/samloader`.

## Project is Active on this Fork.
Former deprecation notice. Please see [STATEMENT.pdf](https://github.com/samloader/samloader/blob/master/STATEMENT.pdf).

### Licensing statement, June 19 2023

I, nlscc, the former maintainer of samloader, make the following statement:
```
LICENSE ADDENDUM STATEMENT

"Relevant Works" are the text of all commits authored by nlscc and uploaded
using the former nlscc GitHub account, insofar as they form a set of
instructions to modify a previous version of the source code (i.e. a set of
diffs), but excluding any text not authored by me but required to implement the
instructions.

The Relevant Works have been released into the public domain. Any previous
licenses applying to the Relevant Works are therefore null.

All rights vested in the Relevant Works, copyright or otherwise (including but
not limited to 'moral' rights), have been irreversibly waived, and
notwithstanding the above nlscc hereby covenants not to attempt to assert the
same.

For the avoidance of doubt this statement does not apply to commits authored by
people who are not nlscc.
```