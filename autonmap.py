import os
import nmap
import csv
import json
import time

def escanear_red(nm):
    print("Escaneando la red...")
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')

    print("IPs encontradas:")
    for host in nm.all_hosts():
        print(f'IP: {host} - Estado: {nm[host].state()}')

def escanear_red_con_puertos_abiertos(nm):
    print("Escaneando la red...")
    nm.scan(hosts='192.168.1.0/24', arguments='-p- -T4 -sV -O')

    print("IPs encontradas con puertos abiertos:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'\nIP: {host} - Estado: {nm[host].state()}')
            print(f'  Sistema Operativo: {nm[host].get("osclass", "Desconocido")}')
            
            for proto in nm[host].all_protocols():
                print(f'  Protocolo: {proto}')
                
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Desconocido')
                        version = nm[host][proto][port].get('version', 'Desconocido')
                        print(f'    Puerto: {port} -> Estado: {state} -> Servicio: {service} -> Versión: {version}')

def escanear_rango_personalizado(ip_range, puerto_range, nm):
    print(f"Escaneando el rango de IP: {ip_range} y puertos: {puerto_range}...")
    nm.scan(hosts=ip_range, arguments=f'-p {puerto_range} -T4 -sV -O')

    print("IPs encontradas con puertos abiertos:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'\nIP: {host} - Estado: {nm[host].state()}')
            print(f'  Sistema Operativo: {nm[host].get("osclass", "Desconocido")}')
            
            for proto in nm[host].all_protocols():
                print(f'  Protocolo: {proto}')
                
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Desconocido')
                        version = nm[host][proto][port].get('version', 'Desconocido')
                        print(f'    Puerto: {port} -> Estado: {state} -> Servicio: {service} -> Versión: {version}')

def guardar_resultados_csv(nm):
    with open('resultados.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP', 'Puerto', 'Estado', 'Servicio', 'Versión', 'Sistema Operativo'])

        for host in nm.all_hosts():
            if nm[host].state() == "up":
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto]:
                        state = nm[host][proto][port]['state']
                        if state == 'open':
                            service = nm[host][proto][port].get('name', 'Desconocido')
                            version = nm[host][proto][port].get('version', 'Desconocido')
                            os_info = nm[host].get('osclass', 'Desconocido')
                            writer.writerow([host, port, state, service, version, os_info])

def guardar_resultados_json(nm):
    data = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Desconocido')
                        version = nm[host][proto][port].get('version', 'Desconocido')
                        os_info = nm[host].get('osclass', 'Desconocido')
                        data.append({
                            "IP": host,
                            "Puerto": port,
                            "Estado": state,
                            "Servicio": service,
                            "Versión": version,
                            "Sistema Operativo": os_info
                        })
    
    with open('resultados.json', 'w') as json_file:
        json.dump(data, json_file, indent=4)

def escanear_rapido(nm):
    print("Escaneo rápido (solo puertos comunes)...")
    nm.scan(hosts='192.168.1.0/24', arguments='-p 22,80,443 -T4')

    print("IPs encontradas con puertos abiertos:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'IP: {host} - Estado: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Desconocido')
                        print(f'  Puerto: {port} -> Estado: {state} -> Servicio: {service}')

def escanear_con_scripts(nm):
    print("Escaneo con scripts de Nmap...")
    nm.scan(hosts='192.168.1.0/24', arguments='--script default -T4')

    print("IPs encontradas con puertos abiertos:")
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'IP: {host} - Estado: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == 'open':
                        service = nm[host][proto][port].get('name', 'Desconocido')
                        print(f'  Puerto: {port} -> Estado: {state} -> Servicio: {service}')

def escanear_por_estado_de_puerto(nm):
    print("Escanear puertos según estado...")
    nm.scan(hosts='192.168.1.0/24', arguments='-p- -T4')

    estado = input("Ingrese el estado de puerto a filtrar (open/closed/filtered): ").strip()
    
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f'\nIP: {host} - Estado: {nm[host].state()}')
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    if state == estado:
                        service = nm[host][proto][port].get('name', 'Desconocido')
                        print(f'  Puerto: {port} -> Estado: {state} -> Servicio: {service}')

def verificacion_puertos_abiertos_servicio(nm):
    ip = input("Ingrese la dirección IP del dispositivo: ")
    puerto = input("Ingrese el puerto a verificar: ")
    nm.scan(hosts=ip, arguments=f'-p {puerto} -sV')
    print(f'Estado del puerto {puerto}: {nm[ip]["tcp"][int(puerto)]["state"]}')
    print(f'Servicio: {nm[ip]["tcp"][int(puerto)]["name"]}')

def escaneo_programado(intervalo, nm):
    while True:
        print("Iniciando escaneo...")
        escanear_red_con_puertos_abiertos(nm)
        print(f"Esperando {intervalo} segundos para el próximo escaneo...")
        time.sleep(intervalo)

os.system('cls||clear')

def mostrar_menu():
    print("\033[31m ▄▄▄       █    ██ ▄▄▄█████▓ ▒█████   ███▄    █  ███▄ ▄███▓ ▄▄▄       ██▓███ \033[0m")
    print("\033[31m▒████▄     ██  ▓██▒▓  ██▒ ▓▒▒██▒  ██▒ ██ ▀█   █ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒\033[0m")
    print("\033[31m▒██  ▀█▄  ▓██  ▒██░▒ ▓██░ ▒░▒██░  ██▒▓██  ▀█ ██▒▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒\033[0m")
    print("\033[31m░██▄▄▄▄██ ▓▓█  ░██░░ ▓██▓ ░ ▒██   ██░▓██▒  ▐▌██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒\033[0m")
    print("\033[31m ▓█   ▓██▒▒▒█████▓   ▒██▒ ░ ░ ████▓▒░▒██░   ▓██░▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░\033[0m")
    print("\033[31m▒▒   ▓▒█░░▒▓▒ ▒ ▒   ▒ ░░   ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░\033[0m")
    print("\033[31m ▒   ▒▒ ░░░▒░ ░ ░     ░      ░ ▒ ▒░ ░ ░░   ░ ▒░░  ░      ░  ▒   ▒▒ ░░▒ ░     \033[0m")
    print("\033[31m ░   ▒    ░░░ ░ ░   ░      ░ ░ ░ ▒     ░   ░ ░ ░      ░     ░   ▒   ░░       \033[0m")
    print("\033[31m ░  ░   ░                  ░ ░           ░        ░         ░  ░         \033[0m")

    print("\033[32m Esta herramienta esta hecha con fines educativos y de prueba. El autor de esta herramienta no se hace responsable de cualquier daño causado por el uso de esta herramienta.\033[0m")
    print("\033[31m NO SEAS UN SKID, SI QUIERES AÑADIR CREDITOS A ELLA ADELANTE, PERO DA CREDITOS\033[0m")

    print("1. Escanear la red")
    print("2. Escaneo de la red junto a puertos abiertos")
    print("3. Escanear un rango personalizado de IPs y puertos")
    print("4. Guardar resultados en archivo CSV o JSON")
    print("5. Escaneo rápido (Solo puertos comunes)")
    print("6. Escaneo con Scripts de Nmap (--script)")
    print("7. Configuración de Prioridad y Tiempo de Escaneo (-T)")
    print("8. Filtrar Resultados por Estado de Puerto")
    print("9. Verificación de Puertos Abiertos con Servicio Específico")
    print("10. Escaneo Programado o Automático")
    print("11. Salir")

def main():
    nm = nmap.PortScanner()
    while True:
        mostrar_menu()
        opcion = input("Ingrese su opción: ")
        
        if opcion == '1':
            escanear_red(nm)
        elif opcion == '2':
            escanear_red_con_puertos_abiertos(nm)
        elif opcion == '3':
            ip_range = input("Ingrese el rango de IPs (por ejemplo, 192.168.1.0/24): ")
            puerto_range = input("Ingrese el rango de puertos (por ejemplo, 22-80): ")
            escanear_rango_personalizado(ip_range, puerto_range, nm)
        elif opcion == '4':
            tipo = input("Seleccione el tipo de archivo (csv/json): ")
            if tipo == 'csv':
                guardar_resultados_csv(nm)
            elif tipo == 'json':
                guardar_resultados_json(nm)
            else:
                print("Opción no válida.")
        elif opcion == '5':
            escanear_rapido(nm)
        elif opcion == '6':
            escanear_con_scripts(nm)
        elif opcion == '7':
            prioridad = input("Ingrese la prioridad (0-5): ")
            nm.scan(hosts='192.168.1.0/24', arguments=f'-T{prioridad} -p- -sV -O')
            print("Escaneo completado con prioridad configurada.")
        elif opcion == '8':
            escanear_por_estado_de_puerto(nm)
        elif opcion == '9':
            verificacion_puertos_abiertos_servicio(nm)
        elif opcion == '10':
            intervalo = int(input("Ingrese el intervalo en segundos para el escaneo programado: "))
            escaneo_programado(intervalo, nm)
        elif opcion == '11':
            print("Saliendo...")
            break
        else:
            print("Opción no válida.")

if __name__ == "__main__":
    main()