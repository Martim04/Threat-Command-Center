# Guia de Funcionamento dos Módulos 🛡️🛰️

O **Threat Command Center** dispõe de **9 módulos táticos** que resolvem diferentes vetores de segurança. Abaixo encontra-se o guia técnico detalhado sobre o funcionamento de cada módulo e as conexões entre o frontend e backend.

---

## 1. Global OSINT Radar 📡
Agrega notícias e informações de inteligência das fontes de segurança mais credíveis do mundo e extrai referências a falhas críticas.
- **Como Funciona:**
  - **Backend (`radar.py`):** Utiliza a biblioteca `feedparser` de forma concorrente para efetuar scraping em fontes selecionadas (ex: CISA Alerts, BleepingComputer, The Hacker News, CERT-PT). Um motor Regex (`CVE-\d{4}-\d{4,7}`) analisa os títulos e resumos para capturar menções a CVEs em tempo real.
  - **Frontend (`app.js` & `home.js`):** Solicita os feeds via `/api/radar` e renderiza-os com badges dinâmicos de criticidade. Exibe também um ticker de movimentação contínua.
- **Fontes Utilizadas:** Feeds RSS de cibersegurança e alertas públicos.

---

## 2. SBOM Scanner 📦
Inspeciona manifestos de dependências de projetos em busca de bibliotecas obsoletas ou vulneráveis.
- **Como Funciona:**
  - **Backend (`sbom.py`):** Faz o parsing de manifestos como `package.json` (Node.js) ou `requirements.txt` (Python). Envia uma série de pedidos HTTP assíncronos em lote (batch requests) para a **Google OSV API** contendo o nome e versão exata de cada biblioteca.
  - **Frontend (`app.js`):** Controla a área de carregamento por arrastamento (Drag & Drop), lê o ficheiro submetido pelo utilizador e envia-o em formato binário multipart para `/api/scanner/analyze`. Os resultados são exibidos através de gráficos de distribuição de severidade (Critical, High, Medium, Low).
- **APIs Conectadas:** Google OSV (Open Source Vulnerabilities) API.

---

## 3. Stack CVE Tracker 🛡️
Efetua a monitorização diária contínua de segurança de toda a infraestrutura de TI registada da organização.
- **Como Funciona:**
  - **Backend (`scanner.py`):** Armazena na base de dados SQLite a stack tecnológica declarada (ex: `nginx:1.20`, `openssl:1.1.1`). Liga-se à **NIST NVD API** para procurar novas vulnerabilidades associadas à stack através do identificador de plataforma (CPE - Common Platform Enumeration).
  - **Frontend (`app.js`):** Disponibiliza uma interface para o administrador registar novas tecnologias, gerando alertas instantâneos com cores reativas se for descoberta uma nova vulnerabilidade no software monitorizado.
- **APIs Conectadas:** NIST NVD (National Vulnerability Database) API.

---

## 4. Global Threat Map 🗺️
Uma representação geográfica em tempo real do ecossistema global de ameaças cibernéticas.
- **Como Funciona:**
  - **Backend (`main.py`):** Processa os dados geográficos extraídos dos feeds de OSINT ou de logs de ataques recentes, convertendo os endereços IP ou nomes de organizações citados em coordenadas geográficas aproximadas de latitude e longitude.
  - **Frontend (`app.js`):** Inicializa e gere o mapa interativo através do **Leaflet.js**. Plota marcadores (blips) com sombras animadas pulsantes que variam de cor consoante a severidade da ameaça associada, exibindo janelas popup informativas ao clicar.
- **Bibliotecas Utilizadas:** Leaflet.js (Frontend), Geolocation Helper (Backend).

---

## 5. Dark Web Monitor 🕸️
Varre de forma constante bases de fugas conhecidas, fóruns ilícitos e canais de comunicação cibercriminosa em busca de ativos corporativos comprometidos.
- **Como Funciona:**
  - **Backend (`darkweb.py`):** Realiza cruzamento de dados de palavras-chave registadas (ex: `dominio.com`, e-mails de utilizadores) contra bases de dados integradas de dumps de credenciais, logs públicos de atividades de Ransomware e feeds do CISA KEV.
  - **Frontend (`app.js`):** Apresenta uma tabela de monitorização avançada onde exibe credenciais comprometidas encontradas, mascarando dados confidenciais e permitindo exportação dos relatórios para formato CSV para análise de remediação.

---

## 6. Supply Chain Detector ⛓️
Protege o pipeline de desenvolvimento de software identificando tentativas de infiltração na cadeia de fornecimento de código.
- **Como Funciona:**
  - **Backend (`supply_chain.py`):** Avalia as dependências fornecidas de forma heurística. Executa cálculos da distância de Levenshtein entre o nome dos pacotes declarados e pacotes altamente populares (ex: detetar `requsts` em vez de `requests`), sinalizando possíveis vetores de **Typosquatting** ou **Dependency Confusion**.
  - **Frontend (`app.js`):** Renderiza avisos visuais marcantes do tipo holograma com badges de recomendação immediata para substituição das dependências maliciosas detetadas.

---

## 7. Attack Path Visualizer 🕸️
Mapeia as vulnerabilidades ativas na infraestrutura contra o framework internacional de táticas e técnicas de atacantes **MITRE ATT&CK**.
- **Como Funciona:**
  - **Backend (`attack_path.py`):** Utiliza um motor probabilístico de grafos para calcular como um atacante poderia penetrar no sistema (Initial Access) aproveitando as falhas ativas monitorizadas no Módulo 3, progredir lateralmente através de falhas locais e obter impacto destrutivo ou exfiltração.
  - **Frontend (`app.js`):** Constrói dinamicamente uma estrutura em árvore hierárquica usando nós CSS interativos, exibindo a probabilidade percentual de exploração em cada nó da cadeia.

---

## 8. NIS2 Compliance Analyzer ⚖️
Garante que a organização cumpre escrupulosamente os exigentes controlos legais da nova diretiva europeia de cibersegurança **NIS2**.
- **Como Funciona:**
  - **Backend (`compliance.py`):** Um motor de regras dinâmico correlaciona a classificação da entidade (Essential vs Important) e os controlos de segurança assinalados pelo utilizador. Adicionalmente, o motor cruza dados de vulnerabilidades ativas (Módulo 3) para subtrair pontuação se houver falhas críticas sem mitigação ativa.
  - **Frontend (`app.js`):** Renderiza um dashboard analítico com gráficos circulares de conformidade geral, identificação detalhada de lacunas legais (Gaps) e gera um roadmap cronológico estruturado de remediação jurídica e técnica.

---

## 9. Auto Scheduler ⚙️
O painel de controlo central que gere a automação das tarefas agendadas em segundo plano.
- **Como Funciona:**
  - **Backend (`scheduler.py`):** Executa rotinas paralelas (background workers) utilizando a framework de concorrência assíncrona do FastAPI. Mantém um histórico de execução e relatórios de falhas de rede na base de dados SQLite.
  - **Frontend (`app.js`):** Monitoriza o estado do Scheduler em `/api/scheduler/status`. Fornece botões de trigger direto (`/api/scheduler/trigger/{job_id}`) que permitem aos operadores de segurança forçar varreduras manuais instantâneas sem acesso à linha de comandos do servidor.
