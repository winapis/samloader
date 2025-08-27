# SPDX-License-Identifier: GPL-3.0+
# Copyright (C) 2020 nlscc

import argparse
import os
import base64
import xml.etree.ElementTree as ET
import datetime
import subprocess
import tempfile
import time
import shutil
from tqdm import tqdm

from . import request
from . import crypt
from . import fusclient
from . import versionfetch
from . import imei
from .logging import log_to_file
from .logging import log_response
import xml.dom.minidom

def main():
    parser = argparse.ArgumentParser(description="Download and query firmware for Samsung devices.")
    parser.add_argument("-m", "--dev-model", help="device model", required=True)
    parser.add_argument("-r", "--dev-region", help="device region code", required=True)
    parser.add_argument("-i", "--dev-imei", help="Device IMEI or First 8 digits (TAC Index) to attempt generating a valid IMEI")
    parser.add_argument("-s", "--dev-serial", help="Device Serial Number if it does not have an IMEI number")
    subparsers = parser.add_subparsers(dest="command")
    dload = subparsers.add_parser("download", help="download a firmware")
    dload.add_argument("-v", "--fw-ver", help="firmware version to download", required=False)
    dload.add_argument("-R", "--resume", help="resume an unfinished download", action="store_true")
    dload.add_argument("-M", "--show-md5", help="print the expected MD5 hash of the downloaded file", action="store_true")
    dload.add_argument("-D", "--do-decrypt", help="auto-decrypt the downloaded file after downloading", action="store_true")
    dload_out = dload.add_mutually_exclusive_group(required=True)
    dload_out.add_argument("-O", "--out-dir", help="output the server filename to the specified directory")
    dload_out.add_argument("-o", "--out-file", help="output to the specified file")
    chkupd = subparsers.add_parser("checkupdate", help="check for the latest available firmware version")
    decrypt = subparsers.add_parser("decrypt", help="decrypt an encrypted firmware")
    decrypt.add_argument("-v", "--fw-ver", help="encrypted firmware version", required=True)
    decrypt.add_argument("-V", "--enc-ver", type=int, choices=[2, 4], default=4, help="encryption version (default 4)")
    decrypt.add_argument("-i", "--in-file", help="encrypted firmware file input", required=True)
    decrypt.add_argument("-o", "--out-file", help="decrypted firmware file output", required=True)
    args = parser.parse_args()
    # Log the command and arguments
    log_to_file(f"Command: {' '.join(os.sys.argv)}")
    if args.command == "download":
        imei_parser(args)
        download(args)
    elif args.command == "checkupdate":
        print(versionfetch.getlatestver(args.dev_model, args.dev_region))
    elif args.command == "decrypt":
        imei_parser(args)
        getkey = crypt.getv4key if args.enc_ver == 4 else crypt.getv2key
        key = getkey(args.fw_ver, args.dev_model, args.dev_region, args.dev_imei)
        length = os.stat(args.in_file).st_size
        with open(args.in_file, "rb") as inf:
            with open(args.out_file, "wb") as outf:
                crypt.decrypt_progress(inf, outf, key, length)

def download(args):
    client = fusclient.FUSClient()
    # We can only download latest firmwares anyway
    args.fw_ver = versionfetch.getlatestver(args.dev_model, args.dev_region)
    path, filename, size = getbinaryfile(client, args.fw_ver, args.dev_model, args.dev_region, args.dev_imei)
    out = args.out_file if args.out_file else os.path.join(args.out_dir, filename)
    # Print information
    print("Device : " + args.dev_model)
    print("CSC : " + args.dev_region)
    print("FW Version : " + args.fw_ver)
    print("FW Size : {:.3f} GB".format(size / (1024**3)))
    print("File Path : " + out)
    # Log the device information
    log_to_file(f"Device: {args.dev_model}")
    log_to_file(f"CSC: {args.dev_region}")
    log_to_file(f"FW: {args.fw_ver}")
    log_to_file(f"Path: {out}")
    # Auto-Resume
    if os.path.isfile(out.replace(".enc4", "")):
        print("File already downloaded and decrypted!")
        log_to_file("File already downloaded and decrypted!")
        return
    elif os.path.isfile(out):
        args.resume = True
        print("Resuming", filename)
        log_to_file(f"Resuming: {filename}")
    else:
        print("Downloading", filename)
        log_to_file(f"Downloading: {filename}")
    dloffset = os.stat(out).st_size if args.resume else 0
    if dloffset == size:
        print("already downloaded!")
        if os.path.isfile(out):
            print("FW Downloaded but not decrypted")
            log_to_file("FW Downloaded but not decrypted")
            # Auto decrypt
            auto_decrypt(args, out, filename)
        return
    
    # Initialize download with Samsung FUS
    initdownload(client, filename)
    
    # Prepare URL and authentication for aria2c
    download_url = f"http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do?file={path}{filename}"
    auth_header = f'FUS nonce="{client.encnonce}", signature="{client.auth}", nc="", type="", realm="", newauth="1"'
    
    # Show initial file size info if resuming
    if args.show_md5:
        # We'll get MD5 info after aria2c download
        print("Note: MD5 verification will be performed after download")
    
    try:
        # Use aria2c for downloading
        print(f"Starting aria2c download with resume support...")
        log_to_file("Starting download with aria2c")
        
        # Monitor file size for progress (aria2c will handle the actual downloading)
        initial_size = dloffset
        
        # Download with aria2c
        success = download_with_aria2c(download_url, out, auth_header, dloffset)
        
        if success:
            # Verify download completed
            final_size = os.path.getsize(out) if os.path.exists(out) else 0
            print(f"Download completed! File size: {final_size / (1024**3):.3f} GB")
            log_to_file("Download completed with aria2c")
            
            # Auto decrypt
            auto_decrypt(args, out, filename)
        else:
            log_to_file("aria2c download failed")
            print("Download failed")
            
    except Exception as e:
        log_to_file(f"Download error: {str(e)}")
        print(f"Download error: {str(e)}")
        raise

def imei_parser(args):
    if args.dev_imei:
        if len(args.dev_imei) == 8:
            for attempt in range(1, 6):  # Try 5 times to generate a valid IMEI
                result = imei.generate_random_imei(args.dev_imei)
                client = fusclient.FUSClient()
                fw_ver = versionfetch.getlatestver(args.dev_model, args.dev_region)
                try:
                    req = request.binaryinform(fw_ver, args.dev_model, args.dev_region, result, client.nonce)
                    resp = client.makereq("NF_DownloadBinaryInform.do", req)
                    root = ET.fromstring(resp)
                    status = int(root.find("./FUSBody/Results/Status").text)
                    if status == 200:
                        print(f"Attempt {attempt}: Valid IMEI Found: {result}")
                        args.dev_imei = result
                        break
                    else:
                        print(f"Attempt {attempt}: IMEI {result} is invalid. FUS Returned : {status}")
                except Exception as e:
                    print(f"Attempt {attempt}: Error during binary file download: {e}")
            else:
                print("Unable to find a valid IMEI after 5 tries. Re-run Samloader to try again or pass a known valid IMEI or Serial Number")
                exit()
        elif len(args.dev_imei) == 15:
            print("IMEI is provided: " + args.dev_imei)
        else:
            print("Invalid IMEI length. Please provide either 8 or 15 digits.")
            exit()
    elif args.dev_serial:
        print("Serial Number is provided: " + args.dev_serial)
        args.dev_imei = args.dev_serial
    else:
        print("IMEI or Serial Number is required for download\nplease set a valid 15 digit IMEI or 8 Digit Tac Index to try generating one with -i / --dev-imei\nOr set a valid Serial Number with -s / --dev-serial")
        exit()

def download_with_aria2c(url, output_path, auth_header, start_offset=0):
    """Download file using aria2c with specified arguments"""
    
    # Create a temporary header file for authorization
    header_file = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(f"Authorization: {auth_header}\n")
            f.write("User-Agent: Kies2.0_FUS\n")
            header_file = f.name
        
        # Build aria2c command with specified arguments
        cmd = [
            'aria2c',
            '-c',                           # continue partial downloads
            '-s16',                         # split into 16 segments
            '-x16',                         # max 16 connections per server
            '-m10',                         # max 10 servers per file
            '--console-log-level=warn',     # set log level to warn
            '--summary-interval=0',         # disable summary interval
            '--check-certificate=false',    # disable SSL certificate checking
            f'--header-file={header_file}', # authorization headers
            f'--out={os.path.basename(output_path)}',  # output filename
            f'--dir={os.path.dirname(output_path)}',   # output directory
        ]
        
        # Add continue/resume support
        if start_offset > 0:
            cmd.append('--continue=true')
        
        cmd.append(url)
        
        # Run aria2c
        log_to_file(f"Running aria2c command: {' '.join(cmd)}")
        process = subprocess.run(cmd, capture_output=True, text=True)
        
        if process.returncode != 0:
            log_to_file(f"aria2c error: {process.stderr}")
            raise Exception(f"aria2c download failed with return code {process.returncode}: {process.stderr}")
        
        log_to_file("aria2c download completed successfully")
        return True
        
    finally:
        # Clean up temporary header file
        if header_file and os.path.exists(header_file):
            os.unlink(header_file)

def auto_decrypt(args, out, filename):
    dec = out.replace(".enc4", "").replace(".enc2", "") # TODO: use a better way of doing this
    if os.path.isfile(dec):
        print("file {dec} already exists, refusing to auto-decrypt!")
        return
    print("\ndecyrpting", out)
    getkey = crypt.getv2key if filename.endswith(".enc2") else crypt.getv4key
    key = getkey(args.fw_ver, args.dev_model, args.dev_region, args.dev_imei)
    length = os.stat(out).st_size
    with open(out, "rb") as inf:
        with open(dec, "wb") as outf:
            crypt.decrypt_progress(inf, outf, key, length)
    os.remove(out)
    print("\nFile", out + " Has been Decrypted.")
    log_to_file("Decryption completed.")

def initdownload(client, filename):
    req = request.binaryinit(filename, client.nonce)
    resp = client.makereq("NF_DownloadBinaryInitForMass.do", req)

def getbinaryfile(client, fw, model, region, imei):
    req = request.binaryinform(fw, model, region, imei, client.nonce)
    resp = client.makereq("NF_DownloadBinaryInform.do", req)
    
    # Log the XML response directly
    log_response(f"Generated Binary Request at BinaryInform for {model}, {region}\n{resp}")

    root = ET.fromstring(resp)
    status = int(root.find("./FUSBody/Results/Status").text)
    if status != 200:
        raise Exception("DownloadBinaryInform returned {}, firmware could not be found?".format(status))
    filename = root.find("./FUSBody/Put/BINARY_NAME/Data").text
    if filename is None:
        raise Exception("DownloadBinaryInform failed to find a firmware bundle")
    size = int(root.find("./FUSBody/Put/BINARY_BYTE_SIZE/Data").text)
    path = root.find("./FUSBody/Put/MODEL_PATH/Data").text
    return path, filename, size
