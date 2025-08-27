# SPDX-License-Identifier: GPL-3.0+
# Copyright (C) 2020 nlscc

import argparse
import os
import base64
import xml.etree.ElementTree as ET
import datetime
import subprocess
import re
from tqdm import tqdm

from . import request
from . import crypt
from . import fusclient
from . import versionfetch
from . import imei
from .logging import log_to_file
from .logging import log_response
import xml.dom.minidom

def validate_aria2c_args(args):
    """Validate aria2c arguments to ensure they are correct."""
    errors = []
    
    # Validate max connections (reasonable range)
    if args.aria2c_max_connections < 1 or args.aria2c_max_connections > 128:
        errors.append("aria2c-max-connections must be between 1 and 128")
    
    # Validate split connections 
    if args.aria2c_split is not None and (args.aria2c_split < 1 or args.aria2c_split > args.aria2c_max_connections):
        errors.append(f"aria2c-split must be between 1 and {args.aria2c_max_connections}")
    
    # Validate min split size format (must be number followed by optional K/M)
    if not re.match(r'^\d+[KM]?$', args.aria2c_min_split_size):
        errors.append("aria2c-min-split-size must be a number optionally followed by K or M (e.g., 1M, 512K)")
    
    # Validate max tries
    if args.aria2c_max_tries < 0 or args.aria2c_max_tries > 100:
        errors.append("aria2c-max-tries must be between 0 and 100")
    
    # Validate retry wait
    if args.aria2c_retry_wait < 0 or args.aria2c_retry_wait > 3600:
        errors.append("aria2c-retry-wait must be between 0 and 3600 seconds")
    
    # Validate timeout
    if args.aria2c_timeout < 1 or args.aria2c_timeout > 3600:
        errors.append("aria2c-timeout must be between 1 and 3600 seconds")
    
    # Validate lowest speed limit format
    if not re.match(r'^\d+[KM]?$', args.aria2c_lowest_speed_limit):
        errors.append("aria2c-lowest-speed-limit must be a number optionally followed by K or M (e.g., 100K, 1M)")
    
    if errors:
        print("Invalid aria2c arguments:")
        for error in errors:
            print(f"  - {error}")
        exit(1)

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
    dload.add_argument("--use-aria2c", help="use aria2c for downloading firmware", action="store_true")
    dload.add_argument("--aria2c-max-connections", type=int, default=32, metavar="N",
                       help="maximum connections per server for aria2c (default: 32 for large files)")
    dload.add_argument("--aria2c-split", type=int, metavar="N",
                       help="number of connections to split download (default: auto-calculated based on file size)")
    dload.add_argument("--aria2c-min-split-size", default="1M", metavar="SIZE",
                       help="minimum size to split (default: 1M, e.g., 5M, 10M)")
    dload.add_argument("--aria2c-max-tries", type=int, default=10, metavar="N",
                       help="maximum number of retries (default: 10)")
    dload.add_argument("--aria2c-retry-wait", type=int, default=10, metavar="SEC",
                       help="seconds to wait between retries (default: 10)")
    dload.add_argument("--aria2c-timeout", type=int, default=60, metavar="SEC",
                       help="timeout in seconds (default: 60)")
    dload.add_argument("--aria2c-lowest-speed-limit", default="50K", metavar="SPEED",
                       help="minimum download speed, restart if slower (default: 50K, e.g., 100K, 1M)")
    dload.add_argument("--aria2c-file-allocation", choices=["none", "prealloc", "falloc"], default="none",
                       help="file allocation method (default: none for faster start)")
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

def download_with_aria2c(client, path, filename, output_path, file_size, args):
    """Download firmware using aria2c with optimized parameters for large files."""
    # Generate authorization headers like the original downloadfile method
    authv = 'FUS nonce="' + client.encnonce + '", signature="' + client.auth \
        + '", nc="", type="", realm="", newauth="1"'
    
    url = f"http://cloud-neofussvr.samsungmobile.com/NF_DownloadBinaryForMass.do?file={path}{filename}"
    
    # Calculate optimal split based on file size if not specified
    if args.aria2c_split is None:
        # For very large files (>5GB), use more connections
        if file_size > 5 * (1024**3):  # 5GB
            optimal_split = min(args.aria2c_max_connections, 64)
        elif file_size > 1 * (1024**3):  # 1GB  
            optimal_split = min(args.aria2c_max_connections, 32)
        else:
            optimal_split = min(args.aria2c_max_connections, 16)
    else:
        optimal_split = args.aria2c_split
    
    # Ensure split doesn't exceed max connections
    optimal_split = min(optimal_split, args.aria2c_max_connections)
    
    aria2c_cmd = [
        "aria2c",
        "-c",  # Continue downloading partially downloaded files
        f"-s{optimal_split}",  # Split connections based on file size
        f"-x{args.aria2c_max_connections}",  # Maximum connections per server
        f"-m{args.aria2c_max_tries}",  # Maximum number of retries
        f"-t{args.aria2c_timeout}",  # Timeout in seconds
        f"--retry-wait={args.aria2c_retry_wait}",  # Wait between retries
        f"--min-split-size={args.aria2c_min_split_size}",  # Minimum split size
        f"--lowest-speed-limit={args.aria2c_lowest_speed_limit}",  # Minimum speed
        f"--file-allocation={args.aria2c_file_allocation}",  # File allocation method
        "--console-log-level=info",  # Show progress and download information
        "--summary-interval=1",  # Show summary every 1 second
        "--check-certificate=false",  # Don't verify SSL certificates
        f"--header=Authorization: {authv}",  # Add authorization header
        f"--header=User-Agent: Kies2.0_FUS",  # Add user agent header
        "-o", os.path.basename(output_path),  # Output filename
        "-d", os.path.dirname(output_path),  # Output directory
        url
    ]
    
    log_to_file(f"Executing aria2c command: {' '.join(aria2c_cmd)}")
    
    # Log configuration summary
    log_to_file(f"aria2c optimizations: connections={optimal_split}/{args.aria2c_max_connections}, "
               f"min_split={args.aria2c_min_split_size}, timeout={args.aria2c_timeout}s, "
               f"retries={args.aria2c_max_tries}, min_speed={args.aria2c_lowest_speed_limit}")
    
    try:
        # Run aria2c without capturing output to show progress to user
        result = subprocess.run(aria2c_cmd, check=True)
        log_to_file("aria2c download completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        log_to_file(f"aria2c download failed: {e}")
        raise Exception(f"aria2c download failed with return code {e.returncode}")
    except FileNotFoundError:
        raise Exception("aria2c not found. Please install aria2c to use this feature.")

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
    
    # Use aria2c for download if requested
    if args.use_aria2c:
        # Validate aria2c arguments first
        validate_aria2c_args(args)
        
        print("Using aria2c for download...")
        print(f"Optimized for large files: {args.aria2c_max_connections} max connections, {args.aria2c_split or 'auto'} split")
        log_to_file("Using aria2c for download")
        log_to_file(f"aria2c config: max_conn={args.aria2c_max_connections}, split={args.aria2c_split or 'auto'}, "
                   f"timeout={args.aria2c_timeout}s, retries={args.aria2c_max_tries}")
        
        # Initialize download with Samsung FUS
        initdownload(client, filename)
        
        # Download with aria2c using optimized settings
        download_with_aria2c(client, path, filename, out, size, args)
        
        log_to_file("Download completed.")
        # Auto decrypt
        auto_decrypt(args, out, filename)
        return
    
    # Original download method
    fd = open(out, "ab" if args.resume else "wb")
    initdownload(client, filename)
    r = client.downloadfile(path+filename, dloffset)
    if args.show_md5 and "Content-MD5" in r.headers:
        print("MD5:", base64.b64decode(r.headers["Content-MD5"]).hex())

    log_interval = size // 10  # Log every 10%
    progress = dloffset

    # Download and log progress
    with tqdm(total=size, initial=dloffset, unit="B", unit_scale=True) as pbar:
        for chunk in r.iter_content(chunk_size=0x10000):
            if chunk:
                fd.write(chunk)
                fd.flush()
                pbar.update(len(chunk))
                
                # Update progress
                progress += len(chunk)
                
                # Check if it's time to log the progress
                if progress >= log_interval:
                    log_to_file(f"Download progress: {progress / (1024**2):.2f} MB / {size / (1024**2):.2f} MB")
                    log_interval += size // 10

    fd.close()
    log_to_file("Download completed.")
    # Auto decrypt
    auto_decrypt(args, out, filename)

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
