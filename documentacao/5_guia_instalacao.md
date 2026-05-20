# Guia de Instalação e Execução 🚀💻

Siga este guia passo-a-passo para instalar, configurar e colocar em execução o **Threat Command Center** no seu ambiente local.

---

## 1. Pré-requisitos do Sistema

Antes de iniciar, certifique-se de que dispõe das seguintes ferramentas instaladas no seu sistema:

-   **Python 3.9+** (Recomendado: Python 3.10 ou superior).
-   **NPM / Node.js** (Apenas se desejar modificar/adicionar dependências de frontend).
-   Um terminal de comandos moderno (Bash ou Zsh em Linux/macOS, ou PowerShell em Windows).

---

## 2. Configuração do Backend (FastAPI)

O backend corre de forma isolada através de uma API em FastAPI. Para o configurar:

### Passo 2.1: Navegar para a pasta backend
Abra o seu terminal e aceda ao diretório correspondente:
```bash
cd backend
```

### Passo 2.2: Criar e Ativar o Ambiente Virtual
O uso de um ambiente virtual (`venv`) evita conflitos de dependências no seu sistema.
-   **macOS / Linux:**
    ```bash
    python -m venv venv
    source venv/bin/activate
    ```
-   **Windows (PowerShell):**
    ```powershell
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    ```

### Passo 2.3: Instalar as Dependências Python
Instale todas as bibliotecas requeridas presentes em `requirements.txt`:
```bash
pip install -r requirements.txt
```
*Caso o ficheiro `requirements.txt` não esteja presente, pode instalar as dependências principais manualmente:*
```bash
pip install fastapi uvicorn requests feedparser python-multipart python-dotenv
```

### Passo 2.4: Configurar Variáveis de Ambiente
O backend utiliza um ficheiro `.env` para carregar as definições.
1.  Duplique o ficheiro de exemplo na raiz do backend:
    ```bash
    cp .env.example .env
    ```
2.  Abra o ficheiro `.env` criado e configure os parâmetros se necessário:
    -   `ALLOWED_ORIGINS`: Origens permitidas para comunicações CORS (ex: `http://localhost:3000`).
    -   `DB_PATH`: Nome do ficheiro SQLite local (padrão: `threat_center.db`).
    -   `LOG_LEVEL`: Nível de verbosidade de logs (`INFO`, `DEBUG` ou `ERROR`).

### Passo 2.5: Iniciar o Servidor FastAPI
Execute o servidor utilizando o motor assíncrono `uvicorn`:
```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```
-   **Modo de Produção:** Retire a flag `--reload` para maior velocidade de execução.
-   **Acesso API Docs:** Aceda a `http://127.0.0.1:8000/docs` no seu navegador para consultar e testar todos os endpoints interativos através do painel automático do Swagger.

---

## 3. Configuração do Frontend (Vanilla)

O frontend é autónomo e consome as APIs de forma assíncrona. Não necessita de qualquer processo de compilação complexo.

### Passo 3.1: Servir o Frontend
Abra um **novo terminal** (mantendo o terminal do backend ativo) e navegue até à pasta correspondente:
```bash
cd frontend
```
Para evitar problemas de segurança de ficheiros locais no carregamento de scripts JS, sirva a pasta estática utilizando o servidor nativo e rápido do Python:
```bash
python -m http.server 3000
```
### Passo 3.2: Aceder à Aplicação
Abra o seu navegador de internet e navegue até ao endereço:
```text
http://localhost:3000
```

---

## 4. Execução Alternativa com Docker (Recomendada) 🐳

Para simplificar a inicialização e evitar a necessidade de configurar ambientes Python locais e múltiplos terminais, o projeto dispõe de suporte completo a **Docker** e **Docker Compose**.

### Passo 4.1: Pré-requisitos do Docker
Garante que tens o **Docker** e o **Docker Compose** instalados na tua máquina:
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (disponível para Windows, macOS e Linux).

### Passo 4.2: Iniciar Toda a Aplicação
Na raiz do projeto (onde se localiza o ficheiro `docker-compose.yml`), executa o seguinte comando no terminal:
```bash
docker-compose up --build
```
Este comando irá:
1. Compilar a imagem do backend FastAPI baseado em `python:3.10-slim`.
2. Fazer o download do servidor web lightweight `nginx:alpine` para servir o frontend.
3. Colocar ambos os serviços em comunicação automática na tua máquina.

### Passo 4.3: Aceder à Aplicação
Após o Docker Compose concluir a inicialização:
- **Frontend (Nginx):** Acede a `http://localhost:3000` no teu browser.
- **Backend (FastAPI):** A API estará exposta em `http://localhost:8000` (e a documentação interativa em `http://localhost:8000/docs`).

Para parar os serviços, prime `Ctrl+C` no terminal ou executa:
```bash
docker-compose down
```

---

## 5. Resolução de Problemas (Troubleshooting) 🛠️

### 4.1 Erros de CORS (Cross-Origin Resource Sharing)
*   **Sintoma:** O dashboard exibe avisos vermelhos ou de "Falha de Conexão à API" e o terminal do browser mostra erros do tipo `Access-Control-Allow-Origin`.
*   **Resolução:** 
    1.  Verifique se o URL em que o seu frontend está a correr (ex: `http://localhost:3000`) está explicitamente listado na variável `ALLOWED_ORIGINS` dentro do ficheiro `backend/.env`.
    2.  Reinicie o servidor FastAPI após alterar o ficheiro `.env`.

### 4.2 Falha de Permissão ou Escrita da Base de Dados SQLite
*   **Sintoma:** O backend encerra abruptamente ao tentar realizar um scan SBOM ou atualizar o OSINT Radar, gerando erros do tipo `OperationalError: attempt to write a readonly database`.
*   **Resolução:** 
    1.  Garante que a conta do sistema operativo que executa o `uvicorn` tem permissões de escrita na pasta `backend/` para criar o ficheiro `threat_center.db`.
    2.  No macOS/Linux, se necessário, ajuste as permissões de acesso da pasta do backend: `chmod -R 755 .`

### 4.3 Falhas de Ligação no Scheduler ou APIs Externas
*   **Sintoma:** O OSINT Radar não carrega novas notícias ou o SBOM Scanner não devolve vulnerabilidades.
*   **Resolução:**
    1.  Verifique se a sua máquina dispõe de ligação direta à Internet sem bloqueios corporativos de firewall.
    2.  A API do Google OSV e do NIST NVD podem impor limites de taxa temporários (rate limits). Verifique os logs do terminal do backend para aferir se existem respostas do tipo HTTP 429.

### 4.4 Portas de Rede Bloqueadas (Port 8000 / 3000 já em uso)
*   **Sintoma:** O uvicorn falha ao iniciar com o erro `[Errno 48] Address already in use`.
*   **Resolução:** 
    1.  Termine o processo órfão que está a ocupar a porta:
        -   No macOS/Linux: `lsof -i :8000` (copie o PID e corra `kill -9 <PID>`).
        -   No Windows: `netstat -ano | findstr 8000` (e termine no Gestor de Tarefas).
    2.  Alternativamente, inicie o backend numa porta livre: `uvicorn main:app --port 8080`. Se o fizer, certifique-se de ajustar as configurações de URL em `frontend/app.js` e `frontend/home.js`.
