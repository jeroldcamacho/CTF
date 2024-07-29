import subprocess

# TCP stream count
TCP_STREAM_NUM = int(subprocess.check_output('tshark -r challenge.pcap -q -z conv,tcp | grep "<->" | wc -l', shell=True).decode())
for num in range(TCP_STREAM_NUM):
    print(f"\nTCP STREAM EQ {num}")
    # extract TCP payloads
    TCP_PAYLOADS = subprocess.check_output(f'tshark -r challenge.pcap -Y "tcp.stream eq {num}" -T fields -e tcp.payload', shell=True).decode().splitlines()

    WHOLE_DATA = []
    # convert TCP payload hex data to ascii
    for data in TCP_PAYLOADS:
        byte_string = bytes.fromhex(data)  
        ascii_data = byte_string.decode("ASCII")  
        numbers = ascii_data.strip('[]').split(', ')
        WHOLE_DATA.append(list(map(int, numbers)))

    MESSAGE = WHOLE_DATA[0::2]
    KEYS = WHOLE_DATA[1::2]

    # decrypt here (message / keys) 
    DECRYPT_MESSAGE = {}
    DATA = ""

    for num in range(len(MESSAGE)):
        for index, (tcp, keys) in enumerate(zip(MESSAGE[num], KEYS[num])):
            DATA += chr(int(tcp / keys))
        print(f"{num} {DATA}")
        DATA = ""