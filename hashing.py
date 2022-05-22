"""CLI based script to hash files and strings"""

def main():
    """Main function"""
    import argparse, hashlib, os, sys, time

    parser = argparse.ArgumentParser(description="Hashing files and strings. Usage: python hashing.py -s string -a md5/sha1/sha256/sha512 -f file -o outputfile -v")
    parser.add_argument("-s", "--string", help="String to hash")
    parser.add_argument("-f", "--file", help="File to hash")
    parser.add_argument("-a", "--algorithm", help="Algorithm to use: MD5, SHA1, SHA64, SHA128, SHA256, SHA512",default="md5")
    parser.add_argument("-v", "--verbose", help="Verbose output", action="store_true")
    parser.add_argument("-o", "--output", help="Output file")
    
    args = parser.parse_args()  
    if args.string:
        string = args.string
        if args.verbose:
            print("String to hash: " + string)
        if args.algorithm == "md5".lower():
            hash_string = hashlib.md5(string.encode('utf-8')).hexdigest()
        elif args.algorithm == "sha1".lower():
            hash_string = hashlib.sha1(string.encode('utf-8')).hexdigest()
        elif args.algorithm == "sha64".lower():
            hash_string = hashlib.sha224(string.encode('utf-8')).hexdigest()
        elif args.algorithm == "sha128".lower():
            hash_string = hashlib.sha256(string.encode('utf-8')).hexdigest()
        elif args.algorithm == "sha256".lower():
            hash_string = hashlib.sha256(string.encode('utf-8')).hexdigest()
        elif args.algorithm == "sha512".lower():
            hash_string = hashlib.sha512(string.encode('utf-8')).hexdigest()
        else: 
            print("Invalid algorithm") 
            sys.exit(1)
        if args.verbose: 
            print("Hash: " + hash_string) 
        if args.output:
            with open(args.output, "a") as f:
                f.write(hash_string + "," + string + "," + args.algorithm + "," + time.strftime("%m/%d/%Y %H:%M:%S") + "\n")
        else:
            print(hash_string)
    elif args.file: # If file is specified
        if args.verbose: # If verbose is specified
            print("File to hash: " + args.file) # Print file to hash
        if args.algorithm == "md5": # If algorithm is md5
            hash_file = hashlib.md5(open(args.file, 'rb').read()).hexdigest() # Hash file
        elif args.algorithm == "sha1": # If algorithm is sha1
            hash_file = hashlib.sha1(open(args.file, 'rb').read()).hexdigest() # Hash file
        elif args.algorithm == "sha64": # If algorithm is sha64
            hash_file = hashlib.sha224(open(args.file, 'rb').read()).hexdigest() # Hash file
        elif args.algorithm == "sha128": # If algorithm is sha128
            hash_file = hashlib.sha256(open(args.file, 'rb').read()).hexdigest() # Hash file
        elif args.algorithm == "sha256": # If algorithm is sha256
            hash_file = hashlib.sha256(open(args.file, 'rb').read()).hexdigest() # Hash file
        elif args.algorithm == "sha512": # If algorithm is sha512
            hash_file = hashlib.sha512(open(args.file, 'rb').read()).hexdigest() # Hash file
        else: # If algorithm is invalid
            print("Invalid algorithm") # Print error
            sys.exit(1) # Exit
        if args.verbose: # If verbose is specified
            print("Hash: " + hash_file) # Print hash
        if args.output: # If output is specified
            with open(args.output, "a") as f: # Open output file
                f.write(hash_file + "," + args.file + "," + args.algorithm + "," + time.strftime("%m/%d/%Y %H:%M:%S") + "\n") 
        else: # If output is not specified
            print(hash_file) # Print hash
    else: # If no arguments are specified
        parser.print_help() # Print help




if __name__ == "__main__":
    main()

