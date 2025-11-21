#!/usr/bin/env python3
import os
import re

def convert_image_links(file_path):
    """Convierte enlaces de imágenes de Obsidian a Jekyll"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Patrón para buscar ![[imagen.png]]
        pattern = r'!\[\[([^]]+\.png)\]\]'
        
        # Función de reemplazo
        def replace_link(match):
            image_name = match.group(1)
            return f'![image-center](/assets/images/{image_name})'
        
        # Reemplazar todas las ocurrencias
        new_content = re.sub(pattern, replace_link, content)
        
        # Solo escribir si hubo cambios
        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True
        return False
    
    except Exception as e:
        print(f"Error procesando {file_path}: {e}")
        return False

def process_directory(directory='.'):
    """Procesa todos los archivos en el directorio"""
    files_modified = 0
    total_replacements = 0
    
    print(f"[*] Buscando archivos en: {os.path.abspath(directory)}")
    print()
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            # Procesar archivos de texto (ajusta las extensiones según necesites)
            if file.endswith(('.md', '.markdown', '.txt')):
                file_path = os.path.join(root, file)
                
                # Leer contenido para contar reemplazos
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Contar cuántas imágenes hay
                    matches = re.findall(r'!\[\[([^]]+\.png)\]\]', content)
                    
                    if matches:
                        print(f"[+] Procesando: {file_path}")
                        print(f"    Imágenes encontradas: {len(matches)}")
                        
                        for img in matches:
                            print(f"    - {img}")
                        
                        if convert_image_links(file_path):
                            files_modified += 1
                            total_replacements += len(matches)
                            print(f"    ✓ Convertido exitosamente")
                        print()
                
                except Exception as e:
                    print(f"[-] Error leyendo {file_path}: {e}")
    
    # Resumen
    print("=" * 50)
    print(f"Resumen:")
    print(f"  Archivos modificados: {files_modified}")
    print(f"  Total de imágenes convertidas: {total_replacements}")
    print("=" * 50)

if __name__ == "__main__":
    print("""
╔════════════════════════════════════════════╗
║  Convertidor de Enlaces de Imágenes       ║
║  Obsidian → Jekyll                         ║
╚════════════════════════════════════════════╝
    """)
    
    # Verificar que el directorio _posts existe
    posts_dir = "_posts"
    
    if not os.path.exists(posts_dir):
        print(f"[-] Error: El directorio '{posts_dir}' no existe")
        print(f"[*] Directorio actual: {os.path.abspath('.')}")
        exit(1)
    
    # Confirmar antes de proceder
    response = input(f"¿Procesar archivos en '{posts_dir}'? (s/n): ")
    
    if response.lower() in ['s', 'si', 'yes', 'y']:
        process_directory(posts_dir)
    else:
        print("[!] Operación cancelada")