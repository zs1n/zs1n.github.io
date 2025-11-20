# Creacion modulo - Thomas Matteucci
# -- Logica principal del modulo
#
# 08/11/2025 - Santiago Cabrera
# -- Incorporacion de Interfaz Unificada
# -- Utilizacion try-except para validar menu
# -- Correccion de rutas segun sistema operativo
#
# 09/11/2025 - Agustin Latrechiana
# -- Incorporación de encapsulamiento de inputs y actions logs

import time
import sys
import helpers
from csvHelpers import get_tabla_from_csv
from IOScreening import patch_input
from template import show_menu, print_con_template

# ================================================

def cargar_problemas_csv():
    """
    carga los problemas desde el archivo 'problemas.csv'.

    args:
        Ninguno.

    returns:
        list: lista de listas, donde cada sublista contiene:
              [nombre_problema, costo, tiempo].
    """
    fallos = []
    with open(helpers.ruta('problemas.csv'), 'r', encoding='utf-8') as file:
        lines = file.readlines()
        for line in lines[1:]:
            partes = line.strip().split(',')
            if len(partes) < 3:
                continue
            nombre = partes[0].strip()
            costo = partes[1].strip()
            tiempo = partes[2].strip()
            fallos.append([nombre, costo, tiempo])
    return fallos

# ================================================

def cargar_datos():
    """
    carga los datos de los barcos desde 'arg.csv' y asigna
    la informacion de problemas correspondiente.

    args:
        Ninguno.

    returns:
        list: lista de barcos, cada uno representado como:
              [nombre, tipo, tiempo_reparacion, costo, problema, criticidad].
    """
    barcos_raw = get_tabla_from_csv(helpers.ruta('arg.csv'), incluir_encabezado=False)
    problemas = cargar_problemas_csv()

    barcos = []
    for barco in barcos_raw:
        gravedad = barco[18]
        try:
            id_problema = int(gravedad)
            if id_problema == -1:
                problema, costo, tiempo = "Reparado", "0", "0"
            elif 0 <= id_problema < len(problemas):
                problema, costo, tiempo = problemas[id_problema]
            else:
                problema, costo, tiempo = "Sin problema", "N/A", "N/A"
        except (ValueError, TypeError):
            problema, costo, tiempo = "Sin problema", "N/A", "N/A"

        criticidad = barco[19]
        barcos.append([barco[0], barco[1], tiempo, costo, problema, criticidad])

    return barcos

# ================================================

def interfaz_seleccion_barco():
    """
    interfaz que permite al usuario seleccionar un barco
    para analizar sus problemas y reparacion.

    args:
        Ninguno.

    returns:
        tuple: (barco_seleccionado, listado_barcos)
               barco_seleccionado (list): barco seleccionado con sus datos.
               listado_barcos (list): lista completa de barcos.
               devuelve None si no hay barcos o si ya esta reparado.
    """

    pantalla = []

    listado_barcos = cargar_datos()
    if not listado_barcos:
        pantalla.append("No hay barcos para reparar.")
        patch_input('Presione enter para continuar.')
        return

    error = ''
    warning = ''
    success = ''
    while True:
        try:

            pantalla = []
            pantalla.append('Seleccione un barco para analizar:')
            pantalla.append('')
            for i, barco in enumerate(listado_barcos):
                pantalla.append(f"{i+1}. {barco[0]} . {barco[1]} . ${barco[3]} . {barco[2]} dias . {barco[4]}")
            pantalla.append('')
            pantalla.append('-1. Volver al menú anterior')
            show_menu(pantalla, error, warning, success)
            error = ''
            warning = ''
            success = ''
            entrada = int(patch_input("Ingrese el numero del barco: "))

            if entrada == -1:
                break

            if not 0 <= entrada < len(barco):
                warning = f'El codigo {entrada} no pertenece a ningun barco. Ingrese un codigo valido.'
                continue

            barco = listado_barcos[entrada + 1]

            if barco[4] == "Reparado":
                warning = f"[!] El barco '{barco[0]}' ya ha sido reparado."
                continue

            error_reparacion = ''
            warning_reparacion = ''
            while True:
                try:
                    pantalla_reparacion = []
                    pantalla_reparacion.append(f"Has seleccionado el barco: {barco[0]}")
                    pantalla_reparacion.append("===============================")
                    pantalla_reparacion.append(f"Tipo de barco: {barco[1]}")
                    pantalla_reparacion.append(f"Problema: {barco[4]}")
                    pantalla_reparacion.append(f"Costo de reparacion: ${barco[3]}")
                    pantalla_reparacion.append(f"Tiempo de reparacion: {barco[2]} días")
                    pantalla_reparacion.append(f"Criticidad: {barco[5]}")
                    show_menu(pantalla_reparacion, error_reparacion, warning_reparacion)
                    error_reparacion = ''
                    warning_reparacion = ''
                    respuesta = patch_input(f"\n¿Desea reparar el barco '{barco[0]}'? "
                                    f"Su proceso lleva {barco[2]} dias y un costo de ${barco[3]} (si/no): ").strip().lower()

                    if respuesta == "si":
                        efectuar_repararacion_barco(barco)
                        marcar_barcos_reparado(barco)
                        break
                    elif respuesta == "no":
                        warning_reparacion = "\n[-] Proceso de reparacion cancelado."
                        break
                    else:
                        warning_reparacion ="Respuesta invalida. Ingrese 'si' o 'no'."
                except ValueError:
                    error_reparacion = 'Error al seleccionar el barco, elija un valor de la lista.'

        except ValueError:
            error = 'Error al seleccionar el barco, elija un valor de la lista.'

# ================================================

def efectuar_repararacion_barco(barco):
    """
    pregunta al usuario si desea reparar el barco seleccionado.

    args:
        barco (list): Barco seleccionado.

    returns:
        list or None: Devuelve el barco reparado si se confirma la reparacion,
                      o None si se cancela o el barco ya estaba reparado.
    """
    pantalla = []
    print_con_template(f"Iniciando el proceso de reparacion para el barco: {barco[0]}", pantalla, False)
    print_con_template("Obteniendo los detalles del daño...", pantalla, False)
    time.sleep(2)
    print_con_template(f"Detalles del daño: {barco[4]}", pantalla, False)
    print_con_template("Reparando el barco...", pantalla, False)
    time.sleep(2)
    print_con_template(f"[+] El barco '{barco[0]}' ha sido reparado con exito.\n", pantalla, False)
    patch_input('Presione enter para continuar.')

# ================================================

def mostrar_barcos_por_criticidad(barcos):
    """
    muestra los barcos agrupados por su nivel de criticidad.

    args:
        barcos (list): Lista de barcos.

    returns:
        dict: diccionario con claves 'Alta', 'Media', 'Baja' y
              valores como listas de barcos correspondientes.
    """
    criticos = {"Alta": [], "Media": [], "Baja": []}
    for barco in barcos:
        nivel = barco[5] if barco[5] in criticos else "Baja"
        criticos[nivel].append(barco)

    pantalla = []
    pantalla.append("=== Barcos por nivel de criticidad ===")
    
    for nivel, lista in criticos.items():
        pantalla.append(f"\n--- Criticidad {nivel} ---")
        if not lista:
            pantalla.append("(Ninguno)")
        else:
            for i, barco in enumerate(lista):
                pantalla.append(f"{i+1}. {barco[0]} ({barco[1]}) - {barco[4]} | Costo: ${barco[3]} | Tiempo: {barco[2]} dias")
    
    show_menu(pantalla)
    return criticos

# ================================================

def elegir_barco_de_criticidad(criticos, nivel):
    """
    Permite al usuario elegir un barco de una criticidad especifica y repararlo.

    args:
        criticos (dict): diccionario de barcos por criticidad.
        nivel (str): nivel de criticidad ('Alta', 'Media', 'Baja').

    returns:
        list or None: barco seleccionado y reparado, o None si se cancela o ya esta reparado.
    """



    if nivel not in criticos or not criticos[nivel]:
        print_con_template(f"No hay barcos con criticidad {nivel}.", [], True)
        patch_input("Presione enter para continuar.")
        return None

    error = ''
    warning = ''
    success = ''
    while True:
        try:
            pantalla = []
            pantalla.append(f"Barcos con criticidad {nivel}:\n")
            for i, barco in enumerate(criticos[nivel]):
                pantalla.append(f"{i+1}. {barco[0]} ({barco[1]}) - {barco[4]} | Costo: ${barco[3]} | Tiempo: {barco[2]} días")
            pantalla.append(f"0. Volver al menú anterior")
            show_menu(pantalla, error, warning, success)
            error = ''
            warning = ''
            success = ''
            seleccion = int(patch_input("Seleccione el número del barco que desea reparar: "))

            if seleccion == 0:
                break

            if not 1 <= seleccion < len(criticos[nivel]):
                warning = f'El codigo {seleccion} no pertenece a ningun barco. Ingrese un codigo valido.'
                continue

            barco = criticos[nivel][int(seleccion)-1]

            if barco[4] == "Reparado":
                warning = f"El barco '{barco[0]}' ya esta reparado. No se puede reparar nuevamente."
                continue

            warning = f"Informacion del barco seleccionado: {barco[0]} ({barco[1]}) - {barco[4]} | Costo: ${barco[3]} | Tiempo: {barco[2]} dias"
            show_menu(pantalla, error, warning, success)

            confirmar = patch_input(f"¿Desea reparar el barco '{barco[0]}'? (si/no): ").strip().lower()
            if confirmar != "si":
                warning = "Operación cancelada."
                continue

            efectuar_repararacion_barco(barco)
        except ValueError:
            error = "Ingrese un valor numerico de los enumerados anteriormente"

    return barco

# ================================================

def marcar_barcos_reparado(barco, ruta_csv='arg.csv'):
    """
    marca un barco como reparado en la lista y en el CSV.

    args:
        barco (list): barco que fue reparado.
        ruta_csv (str, optional): ruta del archivo CSV. por defecto 'arg.csv'.
    """
    nombre_barco = barco[0]
    barco[4] = "Reparado"
    barco[3] = "0"
    barco[2] = "0"

    with open(helpers.ruta(ruta_csv), 'r', encoding='utf-8') as file:
        lines = file.readlines()

    for i, fila in enumerate(lines):
        fila = lines[i].strip().split(',')
        if fila[0] == nombre_barco:
            while len(fila) < 20:
                fila.append('')
            fila[18] = '-1'
            fila[19] = 'Sin Fallos'
            lines[i] = ','.join(fila) + '\n'
            break

    with open(ruta_csv, 'w', encoding='utf-8') as file:
        file.writelines(lines)

    print(f"El barco '{nombre_barco}' ha sido marcado como reparado en el archivo CSV.")

# ================================================

def get_menu_local():
    return [
         'Taller portuario de la Armada Argentina'
        ,''
        ,'Seleccione la accion a realizar:'
        ,'1. Reparar un barco individual'
        ,'2. Mostrar barcos por criticidad'
        ,'3. Reparar un barco por criticidad'
        ,'0. Volver al menú principal'
    ]

def init():
    """
    interfaz principal del módulo de taller
    permite al usuario reparar barcos individualmente, por criticidad, mostrar barcos por criticidad o salir.
    """
    error = ''
    warning = ''
    while True:
        try:
            show_menu(get_menu_local(), error, warning)
            error = ''
            warning = ''
            opcion = int(patch_input("> "))

            barcos = cargar_datos()
            criticos = None

            if opcion == 1:
                barco = interfaz_seleccion_barco()

            elif opcion == 2:
                mostrar_barcos_por_criticidad(barcos)
                patch_input("\nPresione Enter para volver al menu...")

            elif opcion == 3:
                criticos = mostrar_barcos_por_criticidad(barcos)
                nivel = patch_input("Ingrese el nivel de criticidad (Alta/Media/Baja): ").strip().capitalize()
                barco = elegir_barco_de_criticidad(criticos, nivel)
                if barco:
                    marcar_barcos_reparado(barco)
            elif opcion == 0:
                break
            else:
                warning = f"El codigo {opcion} no esta definido. Ingrese un codigo valido."
        except ValueError:
            error = f'Ingrese solamente valores numericos.'
        except Exception as e:
            error = 'Tipo de error no controlado. ' + e
            