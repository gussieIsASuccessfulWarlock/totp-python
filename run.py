import socket
import struct
from rich import print

def save_key(key):
    with open("key.txt", "w") as f:
        f.write(key)

def validate_key(key, outError=True):
    if not key:
        if outError:
            print("Error: Please set your shared secret in the script.")
        return False
    elif len(key) != 36:
        if outError:
            print("Error: Invalid shared secret.")
        return False
    elif not all(c in "0123456789abcdef-" for c in key):
        if outError:
            print("Error: Shared secret must be a hex string.")
        return False
    return True
    
def load_key():
    try:
        with open("key.txt", "r") as f:
            oldKey = f.read()
    except FileNotFoundError:
        oldKey = None
    
    if validate_key(oldKey, False):
        return oldKey
    else:
        newKey = input("Enter your shared secret: ") # e.g. 'f2dbba6f-95c4-4f37-b0d0-a0f0d52d7f22'
        if validate_key(newKey):
            save_key(newKey)
            return newKey
        else:
            exit()
            return None


def get_ntp_time(ntp_server="time.nist.gov", ntp_port=123):
    ntp_delta = 2208988800
    ntp_packet_format = "!12I"
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)

        ntp_packet = b'\x1b' + 47 * b'\0'

        client.sendto(ntp_packet, (ntp_server, ntp_port))
        data, address = client.recvfrom(1024)

        unpacked = struct.unpack(ntp_packet_format, data[:48])
        transmit_timestamp = unpacked[10]
        unix_time = transmit_timestamp - ntp_delta
        return unix_time
    except Exception as e:
        print("Error:", e)
        return None

def get_current_30s_epoch():
    unixtime = get_ntp_time()
    return unixtime - (unixtime % 30)

def get_time_to_expiration():
    current_epoch = get_current_30s_epoch()
    return 30 - (get_ntp_time() - current_epoch)

def get_next_30s_epoch():
    unixtime = get_ntp_time()
    return unixtime - (unixtime % 30) + 30

def generate_mfa_code(shared_secret, epoch=None):
    if epoch is None:
        epoch = get_current_30s_epoch()
    combo = (shared_secret + str(epoch)).encode('utf-8')
    code_int = int.from_bytes(combo, 'little') % 1000000
    return f"{code_int:06d}"

if __name__ == '__main__':
    SHARED_SECRET = load_key()
    code = generate_mfa_code(SHARED_SECRET, get_current_30s_epoch())
    print(f"Your current 6-digit code is:[blue] {code[:3]}-{code[3:]} [/blue] Expires in [red]{get_time_to_expiration()} seconds[/red].")
    next_code = generate_mfa_code(SHARED_SECRET, get_next_30s_epoch())
    print(f"Your next 6-digit code is:[gray] {next_code[:3]}-{next_code[3:]} [/gray] Unlocks in [green]{get_time_to_expiration()} seconds[/green].")
