## 🚀 Instalación y Puesta en Marcha

### 1. Clonar el repositorio

Clona el repositorio en tu máquina local y accede al directorio del proyecto:

```bash
git clone https://github.com/ferfigueirido1/MUniCS-SI-Lab-I.git


cd MUniCS-SI-Lab-I.git
```

---

### 2. Generación del par de claves RSA

Por motivos evidentes de seguridad, este repositorio no incluye ninguna clave privada ni pública.

Para poder ejecutar el cliente, es obligatorio generar un par de claves RSA (módulo de 4096 bits) mediante el comando `ssh-keygen`:

```bash
ssh-keygen -t rsa -b 4096
```

> **Nota:** Este comando creará dos archivos en el directorio actual:
> - `id_rsa`: Clave privada.
> - `id_rsa.pub`: Clave pública.

Ambos ficheros deben residir en la raíz del proyecto, al mismo nivel que los scripts `.py`.

*(Opcional: Si no deseas mantener el archivo `id_rsa.pub` en el directorio, puedes copiar el contenido de tu clave pública y registrarlo directamente bajo tu ID dentro del diccionario en `pubkeys.py`)*.

---

### 3. Requisitos previos

Asegúrate de contar con Python instalado y las dependencias del proyecto:

```bash
pip install cryptography paho-mqtt
```

---

### 4. Ejecución del programa

Inicia el cliente ejecutando el script principal:

```bash
python p1.py
```

Una vez conectado al broker MQTT:
- Introduce el mensaje que deseas transmitir.
- Especifica la ruta de saltos separada por comas (por ejemplo: `ogc,mzp,ffr`).
- Indica si deseas enviar el mensaje de forma anónima (`s` / `n`).
