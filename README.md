# Approfondimenti

## Sandbox -> Ambient virtuale isolato
### Usato per:
  - Emulano all' intrno della macchina corrente ciò che fanno le VM
  - Software testing
  - Protezione durante avvio O.S.
### Pro:
  - Modificabile
  - Protezione da HW e SW
  - Evita conflitti tra O.S. e HW/SW gestiti all'interno dell'ambiente virtuale
### Contro:
  - Sicurezza non perforza garantita
  - Miglioramento ancora in corso
  - Possono rihiedere larghi quantitativi di risorse

## Docker -> Crea container (ambienti virtuali estremamente isolati e leggeri)
### Sono:
  - Spazi isolati comunicanti con l' O.S. tramite un interfaccia
### Differenze rispetto ad una VM:
#### Un container:
   - Servizi innecessari ed è più pratico
   - Gestisce più servizi
#### La VM:
   - Configurazione O.S. necessaria
   - I servizi vanno configurati
### Struttura Container:
(App)C1 <--|
(App)C2 <--|
(App)C3 <--|
           |
        Docker
         / \
          |
  O.S. che hosta Docker
         / \
          |
Infrastruttura (macchina)

### Struttura VM:
O.S. <-- VM1 <-----> VM2 --> O.S.
          |     |     |
         \ /    |    \ /
         APP1   |    APP1
               \ /
Hypervisor (permette virtualizzazione)
               / \
                |
                |
     Infrastruttura (macchina)
           
## Bettercap -> Strumento/framework di sicurezza di rete (pen testing) scritto in Go
### Permette di:
  - Intercettare i dati di protocolli tra cui WIFI e BLE
  - Manipolare i dati
### Utilizzo nel codice:
  - Bettercap è utilizzato per raccogliere dati di tipo BLE, sfrutta la funzione get_ble_data() per raccogliere dai raspberry i dati dei dispositivi localizzati vicini
  - Viene usato sulla porta 8081 (porta TCP), dove viene messo un servizio HTTP ossia un API REST
  - I dati raccolti consistono in RSSI (potenza di segnale) rilevato dal RaspberryPi, di cui è stato fornito l'ip locale, e MAC Adress

 ## Nmap -> Strumento di auditing e network exploration (network mapper)
 ### Permette di:
   - Analizzare dettagliatamente reti
   - Tracciare eventi, azioni all'interno della rete
   - Tracciare dati
   - Rilevare porte aperte
   - Mappare una rete, associando IP e MAC per ogni host
### Utilizzo nel codice:
  - Trova e traccia i dispostitivi che usano l'API REST reso disponibile da bettercup, ossia i RaspberryPi
  - Genera risultati in formato .XML

## Rendering grafico
### Utilizzo radicale della libreria Pyglet:
  - Disegna dei cerchi che rappresentano sostanzialemnte la posizione del dispsositivo trovato
  - Finestra dove vengono rappresenatti i dati raccolti dai 3 RaspberryPi
  - Ogni punto usa delle coordinate X,Y
  - Mostra i MAC dei dispositivi trovati
