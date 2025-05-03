# Librerie necessarie per il funzionamento del programma
# verranno usate dopo
import sys
import math # funzioni matematiche ( potenza, radice quadrata, ecc...)
import socket # libreria generale per usare vari protocolli fra cui TCP e UDP, in questo programma la usiamo solo per prendere l'IP del pc su cui si sta eseguendoimport requests
import subprocess # per eseguire comandi, intesi come comandi nel terminale
import threading # per avviare e gestire thread
import pyglet # per rendering grafico

from bs4 import BeautifulSoup # per leggere il formato XML

positions = []

PORT = 8081 # la porta su cui si esegue bettercap, il servizio web che viene eseguito sui raspberry e ci da le info dei dispositivi bluetooth vicini
HELP_MSG = '''
python3 main.py <args>

-nmap:
    The python script will use nmap to find all available
    bettercap rest API instances on the local network.
-hosts ip1,ip2,ip3,...:
    Manually specify the hosts (alternatively to -nmap).
    You need at least 3 hosts, you can insert more for higher range & precision.
-help:
    you're using it right now.
'''

def rssi2meters(rssi):
    # converte la potenza di segnale di un dispositivo bluetooth in metri
    mp = -59
    N = 3
    return math.pow(10, (mp - rssi) / (10*N))

def triangolazione(c1, c2, c3):
    # c1, c2 e c3 sono 3 cerchi
    # questa funzione calcola l'intersezione
    x1, y1, r1 = c1
    x2, y2, r2 = c2
    x3, y3, r3 = c3

    # Sottraggo la prima equazione dalle altre due
    # ( cosi' i termini al quadrato si tolgono )
    A = 2 * (x2 - x1)
    B = 2 * (y2 - y1)
    C = r1**2 - r2**2 + x2**2 - x1**2 + y2**2 - y1**2

    D = 2 * (x3 - x1)
    E = 2 * (y3 - y1)
    F = r1**2 - r3**2 + x3**2 - x1**2 + y3**2 - y1**2

    # Risoluzione del sistema per y
    if B * D - A * E == 0:
        return None  # Nessuna soluzione

    y = (C * D - A * F) / (B * D - A * E)

    # sostituiamo y in una delle equazioni
    # per trovare x
    if A != 0:
        x = (C - B * y) / A
    else:
        x = (F - E * y) / D

    return (x, y)

def find_scanners(ip, mask = 24):
    # Usa nmap per trovare i raspberry connessi al nostro WiFi con il servizio
    # bettercap online
    # nmap -T4 -A -p {PORT} -oX - {IP}/{SUBNET}

    res = subprocess.Popen(
            # nmap -T4 -p 8081 -oX - 
        ['nmap', '-T4', f'-p {PORT}', '-oX', '-', f'{ip}/{mask}'],
        executable='nmap',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    res.wait() # aspetta che il processo termini

    if res.stdout is None: # se non c'e' output :(
        return None
    
    scan_xml = res.communicate()[0].decode('utf-8') # decodifichiamo l'stdout in utf-8
    bs_data = BeautifulSoup(scan_xml, "xml")

    hosts = []

    # Per ogni dispositivo trovato:
    for result in bs_data.find_all('host'):
        # prendiamo l'IP del dispositivo
        address = result.find('address')['addr']

        # Prendiamo la porta 8081 e controlliamo il suo stato
        ports = result.find('ports')
        port = ports.find('port', attrs={'portid': str(PORT)})
        state = port.find('state')

        # se lo stato e' open o filtered allora va bene
        if state['state'] in ('open', 'filtered'):
            # aggiungiamo quindi il dispositivo alla lista di dispositivi validi
            hosts.append(address)

    # returniamo i dispositivi validi
    return hosts

# prende l'IP del pc su cui stiamo eseguendo sto codice
ME = socket.gethostbyname(socket.gethostname())
if '-nmap' in sys.argv: # se eseguiamo il programma con `python3 main.py -nmap`, allora:
    # usiamo nmap per trovare i raspberry
    print(f'NMAP running at {ME}/24')
    # TODO: Cambiare subnet mask
    host_addrs = find_scanners(ME)
    if host_addrs is None:
        print(f'NMAP Scan failed.')
        exit(1)
    elif len(host_addrs) >= 3:
        print('HOSTS: ' + ','.join(host_addrs))
    else:
        print('Not enough pies!')
        exit(1)
elif '-hosts' in sys.argv: # elif sarebbe 'else if' abbreviato
    # questo e' il caso in cui al posto di eseguire il programma con -nmap specifichiamo noi direttamente gli IP dei raspberry
    host_addrs = sys.argv[sys.argv.index('-hosts')+1].split(',')
    if len(host_addrs) < 3:
        print('You need at least 3 hosts to perform a triangulation attack.')
        exit(1)

elif '-help' in sys.argv: # in caso eseguiamo python3 main.py -help
    print(HELP_MSG)
    exit(1)
else:
    print(HELP_MSG)
    exit(1)

host_coords = {}
# Per ogni raspberry chiediamo la sua posizione nella stanza
for host in host_addrs: # chiede cordinate di ogni raspberry nella stanza
    print(f'Insert the X,Y location for {host}')
    x, y = input('>').split(',')
    x, y = int(x), int(y)

    host_coords[host] = (x, y)

def get_bl_data(ip): # funzione per raccogliere i dati bluetooth dai raspberry 
                      # richiedendoli al server HTTP
    return requests.get(
        f'http://{ip}:{PORT}/api/session/ble'
    ).json()

def getRaspData():
    global positions

    while True:
        res = {}
        for rasp in host_coords:
            # Per ogni raspberry pi online prende i dati bluetooth
            data = get_bl_data(rasp)

            # per ogni dispositivo trovato da quel raspberry
            for device in data['devices']:
                # salviamo le info del dispositivo trovato (rssi, nome, ecc...)
                if device['mac'] in res:
                    res[device['mac']]['distances'][rasp] = device['rssi']
                else:
                    res[device['mac']] = {
                        'name': device['name'],
                        'alias': device['alias'],
                        'last_seen': device['last_seen'],
                        'services': device['services'],
                        'distances': {rasp: device['rssi']}
                    }

        for device in res:
            # Per ognuno dei dispositivi trovati da tutti i raspberry
            distances = res[device]['distances']
            # controlliamo se e' stato trovato da almeno 3 raspberry ( altrimenti non avremmo abbastanza cerchi per fare la triangolazione, ne servono 3 )
            if len(distances.keys()) >= 3:
                
                circles = []
                for rasp in distances: # prende i primi 3 
                    a, b = host_coords[rasp]
                    r = rssi2meters(distances[rasp]) # trasformiamo la potenza di segnale dal rasp al dispositivo in metri
                    circles.append((a, b, r))

                pos = triangolazione(*circles) # eseguiamo la triangolazione
                if pos is None: continue # se la triangolazione e' fallita, skippa
                positions.append((pos[0], pos[1], device)) # altrimenti aggiunge la posizione del dispositivo alla lista


PORT = 8081

WIDTH, HEIGHT = 12, 10.1
WIDTH, HEIGHT = WIDTH*100, HEIGHT*100

# Inizializza la finestra grafica
window = pyglet.window.Window(int(WIDTH), int(HEIGHT))

@window.event
def on_draw():
    window.clear()

    for pos in positions: # per ogni posizione dei dispositivi trovati e triangolati
        # disegna i tre cerchi (rosso, arancio, verde)
        pyglet.shapes.Circle(x=pos[0], y=pos[1], radius=150, color=(114, 196, 134)).draw()
        pyglet.shapes.Circle(x=pos[0], y=pos[1], radius=80, color=(224, 136, 78)).draw()
        pyglet.shapes.Circle(x=pos[0], y=pos[1], radius=30, color=(215, 95, 95)).draw()

        # inserisce un testo con scritto il mac address del dispositivo trovato
        pyglet.text.Label(pos[2],
            font_name='Times New Roman',
            font_size=18,
            x=pos[0], y=pos[1],
            anchor_x='center', anchor_y='center').draw()

# avvia la funzione che prende le informazioni dai raspberry come thread 
# la avvia come thread perche' sia quella che `pyglet.app.run()` bloccano l'esecuzione del codice
# una delle due va eseguita come thread
t = threading.Thread(target=getRaspData)
t.daemon = True
t.start()

pyglet.app.run()


