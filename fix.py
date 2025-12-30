import os
import re
import glob
from pathlib import Path

def escape_liquid_in_file(filepath):
    """
    Escapa código {{ }} que no es Liquid en un archivo markdown
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        original_content = content
        changed = False
        
        # Patrones comunes de código que NO son Liquid
        # 1. Código PowerShell/CMD: {{.Config.Env}}
        # 2. Código PHP: {{$variable}}
        # 3. Código con fetch: {{ fetch("http://
        # 4. Cualquier {{ que no tenga espacio después o sea {% ... %}
        
        # Estrategia: proteger todo {{ }} que no sea claramente Liquid
        # Liquid válido generalmente tiene: {{ site. }}, {{ page. }}, {{ include }}, etc.
        
        # Primero, proteger bloques de código completos
        def protect_code_blocks(match):
            code = match.group(0)
            # Reemplazar {{ por placeholder temporal dentro de bloques de código
            protected = code.replace('{{', 'LIQUID_OPEN_TEMP')
            protected = protected.replace('}}', 'LIQUID_CLOSE_TEMP')
            return protected
        
        # Proteger bloques de código ```
        content = re.sub(r'```[\s\S]*?```', protect_code_blocks, content)
        
        # Proteger bloques de código indented (4 espacios)
        content = re.sub(r'(?m)^(\s{4,}.*\n)+', protect_code_blocks, content)
        
        # Ahora, escapar {{ }} restantes que no sean Liquid
        # Liquid típico: {{ site.title }}, {{ page.url }}, {{ include file }}, etc.
        liquid_patterns = [
            r'\{\{\s*site\.\w+',
            r'\{\{\s*page\.\w+',
            r'\{\{\s*layout\.\w+',
            r'\{\{\s*include\s+',
            r'\{\{\s*content\s*\}\}',
            r'\{\{\s*post\.\w+',
            r'\{\{\s*for\s+',
            r'\{\{\s*if\s+',
            r'\{\{\s*else\s*\}\}',
            r'\{\{\s*endif\s*\}\}',
            r'\{\{\s*endfor\s*\}\}',
            r'\{\{\s*assign\s+',
        ]
        
        # Función para determinar si es Liquid
        def is_liquid_code(text):
            for pattern in liquid_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return True
            return False
        
        # Encontrar todos los {{ }} y verificar
        def escape_non_liquid(match):
            full_match = match.group(0)
            if is_liquid_code(full_match):
                return full_match  # Es Liquid, mantener
            else:
                # No es Liquid, escapar
                escaped = full_match.replace('{{', '{% raw %}{{')
                escaped = escaped.replace('}}', '}}{% endraw %}')
                return escaped
        
        # Aplicar a todo el contenido
        content = re.sub(r'\{\{[^{}]*?\}\}', escape_non_liquid, content)
        
        # También buscar {{ sin cerrar (como en el error)
        def escape_unclosed_liquid(match):
            text = match.group(0)
            # Si ya tiene {% raw %} o es claramente Liquid, dejar
            if '{% raw %}' in text or is_liquid_code(text):
                return text
            # Escapar
            escaped = text.replace('{{', '{% raw %}{{')
            # No cerrar }} si no está presente
            if '}}' in text:
                escaped = escaped.replace('}}', '}}{% endraw %}')
            return escaped
        
        # Para casos como {{ fetch("http://{ip}' (sin cerrar)
        content = re.sub(r'\{\{[^{}]*', escape_unclosed_liquid, content)
        
        # Restaurar los placeholders en bloques de código
        content = content.replace('LIQUID_OPEN_TEMP', '{{')
        content = content.replace('LIQUID_CLOSE_TEMP', '}}')
        
        # Verificar si hubo cambios
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
        
    except Exception as e:
        print(f"  Error procesando {filepath}: {e}")
        return False

def find_problematic_files():
    """
    Encuentra archivos que tienen código {{ problemático
    """
    problematic = []
    
    # Patrones que sabemos causan error
    error_patterns = [
        r'\{\{\.[^{}]*\}\}',      # {{.Config.Env}}
        r'\{\{\$[^{}]*\}\}',       # {{$variable}}
        r'\{\{\s*fetch\(',         # {{ fetch(
        r'\{\{[^{}]*\{[^{}]*',     # {{ algo { algo (sin cerrar bien)
    ]
    
    for filepath in glob.glob('_posts/*.md'):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for pattern in error_patterns:
                if re.search(pattern, content):
                    problematic.append(filepath)
                    break
        except:
            continue
    
    return problematic

def main():
    print("=== Escapando código Liquid problemático ===\n")
    
    # Opción 1: Procesar archivos específicos mencionados en el error
    specific_files = [
        '_posts/2025-11-28-Busqueda.md',      # Línea 183: {{.Config.Env}}
        '_posts/2025-12-10-Minion.md',        # Línea 222: {{$ip.Send(...)}}
        '_posts/2025-12-17-Alert.md',         # Línea 239: {{ fetch("http://{ip}'
    ]
    
    print("1. Procesando archivos específicos con error:")
    for filepath in specific_files:
        if os.path.exists(filepath):
            print(f"  • {Path(filepath).name}")
            if escape_liquid_in_file(filepath):
                print(f"    ✓ Arreglado")
            else:
                print(f"    ✗ No se encontraron problemas")
        else:
            print(f"  • {filepath} (no encontrado)")
    
    # Opción 2: Buscar automáticamente archivos problemáticos
    print("\n2. Buscando más archivos problemáticos...")
    problematic = find_problematic_files()
    
    if problematic:
        print(f"  Encontrados {len(problematic)} archivos potencialmente problemáticos:")
        for filepath in problematic:
            filename = Path(filepath).name
            if filepath not in specific_files:  # No procesar los ya procesados
                print(f"  • {filename}")
                if escape_liquid_in_file(filepath):
                    print(f"    ✓ Arreglado")
    else:
        print("  No se encontraron más archivos problemáticos")
    
    # Opción 3: Procesar TODOS los archivos (más agresivo)
    print("\n3. ¿Deseas procesar TODOS los archivos en _posts/? (y/n)")
    choice = input("   > ").strip().lower()
    
    if choice == 'y':
        all_files = glob.glob('_posts/*.md')
        print(f"  Procesando {len(all_files)} archivos...")
        
        fixed_count = 0
        for i, filepath in enumerate(all_files, 1):
            filename = Path(filepath).name
            print(f"  [{i}/{len(all_files)}] {filename}", end='')
            
            if escape_liquid_in_file(filepath):
                print(" ✓")
                fixed_count += 1
            else:
                print(" ✓ (sin cambios)")
        
        print(f"\n  Total: {fixed_count} archivos modificados")
    
    print("\n=== Proceso completado ===")
    print("\nAhora ejecuta:")
    print("  git add _posts/")
    print("  git commit -m 'Escapar código Liquid problemático'")
    print("  git push origin master")

if __name__ == "__main__":
    # Cambiar al directorio del repositorio si es necesario
    repo_path = r"C:\zs1n.github.io"
    if os.path.exists(repo_path):
        os.chdir(repo_path)
        print(f"Directorio cambiado a: {repo_path}")
    
    main()