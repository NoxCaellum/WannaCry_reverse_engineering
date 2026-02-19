#############################################################################
### Author: NoxCaellum
### Date: 02/18/2026
### This programme extract encrypted_aes_key and large_chunk.bin of t.wnry
#############################################################################


import os
import sys

INPUT_FILE = "t.wnry"

# Extract encrypted AES key (256 bytes starting at offset 12)
AES_OFFSET = 12
AES_LENGTH = 256
AES_OUTPUT = "encrypted_aes_key"

# Extract encrypted chunk (from offset 280 to end)
CHUNK_OFFSET = 280
CHUNK_OUTPUT = "large_chunk.bin"


def extract_portion(source_path, output_path, offset, length=None):
    try:
        with open(source_path, "rb") as f_in:
            f_in.seek(offset)
            if length is not None:
                data = f_in.read(length)
            else:
                data = f_in.read()

            if not data:
                print(f"[!] Nothing read at offset {offset}")
                return False

            with open(output_path, "wb") as f_out:
                f_out.write(data)

            size_str = f"{len(data)} bytes" if length else "to end of file"
            print(f"[+] Extracted {size_str} -> {output_path}")
            return True

    except FileNotFoundError:
        print(f"[!] File not found: {source_path}")
        return False
    except PermissionError:
        print(f"[!] Permission denied: {source_path}")
        return False
    except Exception as e:
        print(f"[!] Error during extraction: {e}")
        return False


def main():
    if not os.path.isfile(INPUT_FILE):
        print(f"[!] File does not exist: {INPUT_FILE}")
        sys.exit(1)

    print(f"[*] Processing file: {INPUT_FILE}")
    print(f"[*] Total size: {os.path.getsize(INPUT_FILE):,} bytes\n")

    success_aes = extract_portion(INPUT_FILE, AES_OUTPUT, AES_OFFSET, AES_LENGTH)
    success_chunk = extract_portion(INPUT_FILE, CHUNK_OUTPUT, CHUNK_OFFSET)

    print("\nResult:")
    print(f"  - {AES_OUTPUT:<18} : {'OK' if success_aes else 'FAILED'}")
    print(f"  - {CHUNK_OUTPUT:<18} : {'OK' if success_chunk else 'FAILED'}")

    if success_aes and success_chunk:
        print("\nExtraction completed successfully.")
    else:
        print("\nSome extractions failed.")


if __name__ == "__main__":
    main()