# Resplandor
Repositorio PIA el mejor auditor de tout le monde
todes respaldamos esta informacion.
asegúrate de tener descargados los repositorios adecuados tanto como las librerías de Python y mantener actualizado tu powershell recuerda que este código solo es de uso educativo.la función de replicarse en otras maquinas solo esta permitida fuera de organizaciones y con el consentimiento del usuario, recuerda tener almacenamiento suficiente para poder replicar tu ram 

Resplandor
Propósito 
Hacer un código capaz de auditar computadoras séase ver los logs de la computadora, capturar la RAM, replicarse en entornos controlados para que puedas auditar las maquinas de tu hogar desde tu maquina principal

Rol esperado SOC
Entradas esperadas (formato y ejemplos)
| Tipo                  | Descripción                                            | Ejemplo                      |
| --------------------- | ------------------------------------------------------ | ---------------------------- |
| Parámetro de fecha    | Fecha desde la cual se quieren revisar los logs.       | `-Desde 2025-10-01`          |
| Clave AbuseIPDB       | API Key del servicio para validar reputación de IPs.   | `-ClaveAbuse "abcd1234"`     |
| Opción de captura RAM | Indicador booleano para decidir si se captura memoria. | `-CapturarRAM`               |
| Directorio de salida  | Carpeta donde se guardarán los resultados.             | `-SalidaBase "C:\Auditoria"` |



Salidas esperadas (formato y ejemplos)
| Tipo               | Descripción                                   | Ejemplo                               |
| ------------------ | --------------------------------------------- | ------------------------------------- |
| `.csv / .html`     | Registros de eventos del sistema y seguridad. | `eventos\Security_20251105.csv`       |
| `.csv / .html`     | Procesos activos y conexiones de red.         | `procesos\procesos_red_20251105.html` |
| `.txt`             | Resumen general del análisis.                 | `Resumen_Forense.txt`                 |
| `.raw` y `.sha256` | Imagen de RAM y su hash de integridad.        | `RAM_Capture_20251105.raw`            |




Recuerda no tener activado Set-StrictMode

Descripción del procedimiento (narración funcional)
El usuario ejecutara el código y selecionara si quiere ver los logs filtrados,capturar la ram,o vereificar si esta compremetida su maquina con adbuse ipbd y posteriormente se verán las maquinas cercanas para ver si se puede replicar en esas maquninas 
Complejidad técnica (dimensiones que cubre)
Tiene mucha complejidad técnica ya que se usa la replicación y se tienen que verificar los puertos para ver si es se puede replicar tanto como saber usar y replicar la ram para poder utilizarla 
Controles éticos o consideraciones éticas que se tomarán en cuenta
No se puede replicar en maquinas que no acepten la replicación 
Dependencias (librerías, comandos, entorno)

| Tipo                               | Requisito                                                                      |
| ---------------------------------- | ------------------------------------------------------------------------------ |
| **Entorno**                        | PowerShell 5.1 o superior (Windows 10/11)                                      |
| **Herramienta externa (opcional)** | `winpmem.exe` para captura de RAM                                              |
| **Comandos PowerShell**            | `Get-WinEvent`, `Get-NetTCPConnection`, `Get-CimInstance`, `Invoke-RestMethod` |
| **Conectividad**                   | Internet (solo para consultas a AbuseIPDB)                                     |
| **Almacenamiento**                 | Espacio suficiente para guardar imágenes de memoria y reportes                 |

Declaración ética y legal
Este proyecto se desarrollará exclusivamente con datos sintéticos o simulados. No se utilizarán datos reales, credenciales privadas ni información sensible. Todos los experimentos se ejecutarán en entornos controlados.  
El equipo se compromete a documentar cualquier riesgo ético y aplicar medidas de mitigación adecuadas.

Roles 
Líder de proyecto / SOC Analyst
Francisco Cruz Zapata
Coordina las tareas del equipo, gestiona la ejecución del proyecto y revisa los resultados de auditoría. Supervisa la correcta recolección de logs y asegura el cumplimiento ético del desarrollo.

DFIR Specialist (Digital Forensics & Incident Response)
Emilio Gonzales Vargas
Encargado de la captura de memoria RAM con WinPmem y del análisis forense de los eventos del sistema. Verifica la integridad de las evidencias mediante hashing (SHA256).


Red Team / Pentester
Issac Abid Maldonado Sánchez
Desarrolla y prueba la función de replicación controlada dentro de entornos autorizados. Evalúa la superficie de ataque y garantiza que la herramienta no se use fuera de entornos seguros.


Blue Team / Seguridad Defensiva
Alan Milán Vázquez
Supervisa el comportamiento del script frente a controles defensivos (firewall, antivirus, permisos). Apoya en la revisión de falsos positivos y en la protección del entorno de prueba

DevOps / Automatización y Documentación
Carlos Giovanni Reyes Medina
Responsable del mantenimiento del repositorio en GitHub, la estructura de carpetas (/src, /docs, /proposals, /examples), la documentación técnica (README.md) y la integración del flujo de trabajo.

Segundo entregable – MVP funcional parcial
Objetivo:
Implementar al menos una tarea funcional del proyecto con resultados verificables.
Estado actual:
Se completó una tarea funcional en /src (auditoría de logs).
Se añadieron ejemplos de salida y logs en formato JSON lines en /examples.
Script ejecutable disponible: run_tarea1.py.
Documentación técnica básica en /docs/entregable_2.md.
README actualizado con el estado del proyecto.
Evidencia reproducible:

Archivos generados en /examples.
Logs estructurados en .json.
Ejecución controlada mediante script.

Tercer entregable del Proyecto Final PIA – Integración parcial y plan de IA
Se integraron dos tareas del proyecto: auditoría de logs y revisión de procesos/red, con flujo técnico entre módulos en Python.
Se agregó un script principal que conecta ambas funciones y genera logs estructurados en /examples/logs.jsonl.
El plan de IA se documentó en /docs/ai_plan.md y la plantilla inicial de prompt en /prompts/.
El proyecto ahora incluye orquestación básica y documentación del avance en /docs/entregable_3.md.
Se actualizó este README con el estado actual del proyecto.


Estado del Proyecto – Entregable 4

Para este cuarto entregable se integró casi todo el flujo técnico del proyecto.
Ya se conectaron las tareas principales (eventos, procesos/red y reputación de IPs), y se agregó la parte de IA que usamos solo para organizar la salida y apoyar en la interpretación del análisis. También se generaron ejemplos reproducibles dentro de /examples y se actualizó el sistema de logs en formato JSON lines.

El proyecto ya corre como un flujo casi completo, faltando únicamente los detalles finales para la entrega. 

Para este último entregable se completó todo el proyecto. Ya están integradas todas las tareas, el flujo técnico funciona de inicio a fin y se agregó el uso básico de IA como parte del proceso. También se generó la evidencia reproducible y se dejaron los logs en formato JSON.

El repositorio quedó organizado, funcional y con la documentación final del proyecto. Con esto se cierra formalmente el trabajo del PIA.

Entregable 5 – Repositorio completo y cierre del proyecto

En este último entregable se realizó el cierre completo del proyecto. El repositorio ya está funcional, organizado y con todos los módulos integrados. Todas las tareas del proyecto trabajan en conjunto dentro del flujo técnico principal y se generó la evidencia necesaria para demostrar su funcionamiento.

Repositorio completo

El repositorio contiene todo lo desarrollado durante el proyecto, incluyendo código, ejemplos de ejecución, documentación y el uso básico de IA. La estructura quedó organizada para facilitar la ejecución, revisión y validación de cada parte del proyecto.

Tareas implementadas
Las tareas principales del sistema ya están integradas:
Obtención y filtrado de eventos.
Análisis de procesos y conexiones de red.
Consulta de reputación de IPs.

Integración básica de IA para apoyar en la interpretación o generación de textos.
Estas funciones trabajan juntas como un solo flujo.

Scripts y ejecución
El proyecto cuenta con un flujo completo que puede ejecutarse desde un script principal. El sistema genera sus carpetas de salida, evidencia y registros sin intervención manual.

Evidencia reproducible
El repositorio ya incluye ejemplos generados por el propio programa:
Salidas de auditoría.
Reportes y tablas.
Carpeta de evidencia con ejemplos.
Logs en formato JSON.
Esta evidencia muestra el funcionamiento real del proyecto.
Logging

El proyecto produce registros estructurados, con información esencial del flujo como:
Timestamp
Módulo
Nivel del evento
Detalles relevantes
Esto permite rastrear la ejecución completa y validar que el flujo trabaja de manera consistente.

Uso de IA
La IA se integró de forma funcional dentro del flujo.
Se utiliza para apoyar en la organización y explicación de resultados y cuenta con su plantilla de prompt inicial. Su integración quedó documentada.

Documentación final
El repositorio incluye documentación del proceso, explicaciones del flujo técnico y el resumen del estado final del proyecto. También se documentaron ajustes relevantes hechos durante el desarrollo.

Colaboración del equipo
El repositorio refleja la participación activa del equipo mediante:

Commits

Cambios constantes
Aportes en diferentes partes del código

Cierre
Con este entregable se concluye formalmente el proyecto.
El repositorio está completo, funcional y contiene todo lo necesario para su evaluación final.
