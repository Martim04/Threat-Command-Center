# Documentação do Backend e APIs ⚙️🔌

O backend do **Threat Command Center** é desenvolvido em **FastAPI (Python 3.9+)**. O sistema utiliza uma estrutura de ficheiros modular, onde cada componente é responsável por um vetor específico de inteligência ou automação.

---

## 📂 Arquitetura de Ficheiros do Backend

- **`main.py`:** O ponto de entrada da aplicação. Inicializa a aplicação FastAPI, configura o middleware de CORS, regista as rotas da API REST, gere o ciclo de vida da aplicação (startup/shutdown) e orquestra a comunicação entre os restantes módulos.
- **`database.py`:** Camada de persistência relacional. Gere a conexão SQLite (`threat_center.db`), cria o esquema de tabelas inicial (históricos, stack tecnológica, alertas e credenciais monitorizadas) e disponibiliza funções utilitárias para queries assíncronas/síncronas.
- **`scheduler.py`:** Motor de automação assíncrono em segundo plano (background worker). Gerencia tarefas cíclicas de longa duração (ex: atualizar feeds RSS a cada 6h, realizar varreduras automatizadas NVD a cada 12h) e expõe controlos para monitorização e triggers manuais.
- **`radar.py`:** Agregador de inteligência de código aberto (OSINT). Efetua scraping concorrente e assíncrono de feeds RSS (CISA, BleepingComputer, etc.), processa conteúdos com expressões regulares para identificar referências a CVEs e correlaciona dados temporais.
- **`scanner.py`:** Motor principal de análise de vulnerabilidades. Integra-se com a NIST NVD API para obter detalhes de vulnerabilidades (scores CVSS, descrições, severidade) associadas à Stack do utilizador.
- **`sbom.py`:** Motor de validação de Software Bill of Materials (SBOM). Faz o parsing estruturado de manifestos de pacotes (`requirements.txt`, `package.json`, etc.) e submete as dependências para a Google OSV (Open Source Vulnerabilities) API.
- **`supply_chain.py`:** Módulo de segurança preventiva. Verifica o manifesto em busca de vetores de ataques modernos como *Typosquatting* (comparação de distâncias de Levenshtein contra bibliotecas populares) e anomalias de nomes.
- **`darkweb.py`:** Motor de varredura profunda de leaks e Pastebins. Procura domínios, palavras-chave e e-mails definidos na base de dados em feeds de ameaças conhecidos, logs de ransomware e repositórios CISA KEV (Known Exploited Vulnerabilities).
- **`attack_path.py`:** Simula caminhos de ataque de forma probabilística. Mapeia as vulnerabilidades ativas na infraestrutura contra táticas do framework MITRE ATT&CK, desenhando grafos lógicos de invasão.
- **`compliance.py`:** Motor analítico de conformidade legal. Avalia a infraestrutura tecnológica ativa e as vulnerabilidades conhecidas face aos requisitos obrigatórios da Diretiva Europeia NIS2, sugerindo planos táticos de ação.
- **`logger.py`:** Centraliza e formata o output de depuração no terminal e ficheiros locais, facilitando o diagnóstico em produção.

---

## 📡 Referência de Rotas da API REST

*Nota: Todas as rotas assumem o prefixo `http://localhost:8000`. Os inputs e outputs são estruturados em JSON.*

### 1. Sistema & Saúde (`/api`)
- **GET `/api/health`**
  - **Descrição:** Verifica se a base de dados SQLite, o scheduler e os serviços externos estão operacionais.
  - **Resposta (200 OK):**
    ```json
    {
      "status": "healthy",
      "database": "connected",
      "scheduler": "active",
      "uptime_seconds": 12450
    }
    ```

### 2. OSINT Radar (`/api/radar`)
- **GET `/api/radar`**
  - **Descrição:** Devolve a lista de artigos do feed OSINT processados na base de dados.
  - **Query Params:** `limit` (int, default=50), `source` (string, opcional).
  - **Resposta:** Lista de objetos contendo `id`, `title`, `link`, `source`, `published_date`, `cves_detected`.
- **POST `/api/radar/refresh`**
  - **Descrição:** Força o motor a executar imediatamente o scraping assíncrono dos feeds RSS e processar novas CVEs por Regex.
- **GET `/api/radar/stats`**
  - **Descrição:** Devolve estatísticas globais sobre o feed (total de menções, severidades mais citadas, principais fontes).

### 3. SBOM Scanner (`/api/scanner`)
- **POST `/api/scanner/analyze`**
  - **Descrição:** Recebe um manifesto de dependências e consulta a base de dados do Google OSV.
  - **Content-Type:** `multipart/form-data`
  - **Form-Data:** `file` (Ficheiro `package.json` ou `requirements.txt`).
  - **Resposta:**
    ```json
    {
      "filename": "requirements.txt",
      "total_dependencies": 15,
      "vulnerabilities_found": 3,
      "severity_summary": { "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0 },
      "details": [
        {
          "package": "requests",
          "version": "2.25.0",
          "cve": "CVE-2021-33503",
          "severity": "HIGH",
          "summary": "Urllib3 before 1.26.5 allows ...",
          "details_url": "https://osv.dev/vulnerability/..."
        }
      ]
    }
    ```
- **GET `/api/scanner/history`**
  - **Descrição:** Recupera o histórico de scans SBOM guardados na base de dados SQLite.

### 4. Stack CVE Tracker (`/api/tracker`)
- **GET `/api/tracker/stack`**
  - **Descrição:** Devolve a stack tecnológica monitorizada da empresa (ex: `nginx:1.20`, `ubuntu:20.04`).
- **POST `/api/tracker/stack`**
  - **Descrição:** Regista um novo componente tecnológico para monitorização de segurança.
  - **Body (JSON):** `{"name": "nginx", "version": "1.20"}`
- **DELETE `/api/tracker/stack/{name}`**
  - **Descrição:** Remove o item especificado da stack de monitorização.
- **POST `/api/tracker/scan`**
  - **Descrição:** Inicia uma pesquisa em tempo real à NIST NVD API para todos os itens registados na stack.
- **GET `/api/tracker/alerts`**
  - **Descrição:** Obtém todos os alertas de CVEs detetados na stack da organização.

### 5. Auto Scheduler (`/api/scheduler`)
- **GET `/api/scheduler/status`**
  - **Descrição:** Devolve a lista de tarefas agendadas em segundo plano, horários de execução futura e logs de status.
- **POST `/api/scheduler/trigger/{job_id}`**
  - **Descrição:** Executa manualmente e de imediato a tarefa assíncrona correspondente ao ID indicado (ex: `radar_refresh_job`, `cve_scanner_job`).

### 6. Threat Map (`/api/threatmap`)
- **GET `/api/threatmap/events`**
  - **Descrição:** Devolve uma lista de eventos com dados de geolocalização IP/País inferidos a partir dos feeds de ameaças recentes para marcação visual.
- **GET `/api/threatmap/stats`**
  - **Descrição:** Devolve métricas de distribuição regional de ameaças (países com maior taxa de atividade maliciosa relatada).

### 7. Dark Web Monitor (`/api/darkweb`)
- **GET `/api/darkweb/targets`**
  - **Descrição:** Devolve os alvos de monitorização registados (e-mails, domínios corporativos).
- **POST `/api/darkweb/targets`**
  - **Descrição:** Adiciona um novo alvo de monitorização.
  - **Body (JSON):** `{"keyword": "empresa.com"}`
- **DELETE `/api/darkweb/targets/{keyword}`**
  - **Descrição:** Remove um alvo monitorizado.
- **POST `/api/darkweb/scan`**
  - **Descrição:** Corre a análise sobre os alvos registados em bases de fugas públicas conhecidas e Pastebins.
- **GET `/api/darkweb/findings`**
  - **Descrição:** Obtém todas as credenciais expostas ou menções críticas encontradas.
- **POST `/api/darkweb/breach-check`**
  - **Descrição:** Faz a validação instantânea de um e-mail único contra as bases de violações.

### 8. Supply Chain Security (`/api/supply-chain`)
- **POST `/api/supply-chain/analyze`**
  - **Descrição:** Avalia ficheiros de dependências aplicando regras heurísticas de cibersegurança (Typosquatting de nomes conhecidos, dependências fantasmas).

### 9. Attack Path Simulation (`/api/attack-path`)
- **GET `/api/attack-path`**
  - **Descrição:** Constrói uma representação lógica em árvore dos caminhos de invasão prováveis baseando-se nas vulnerabilidades encontradas na stack tecnológica da organização, mapeadas diretamente contra o framework MITRE ATT&CK.

### 10. Conformidade NIS2 (`/api/compliance`)
- **POST `/api/compliance/nis2`**
  - **Descrição:** Avalia o nível de prontidão face aos requisitos NIS2 baseando-se nos controlos implementados e nas vulnerabilidades ativas.
  - **Body (JSON):**
    ```json
    {
      "entity_type": "ESSENTIAL",
      "controls_implemented": ["mfa", "backup", "incident_response"]
    }
    ```
  - **Resposta:**
    ```json
    {
      "overall_score": 62,
      "overall_status": "PARTIAL COMPLIANCE",
      "critical_gaps": 4,
      "top_gaps": [
        {
          "article": "Art. 21.2(d)",
          "title": "Supply Chain Security",
          "score": 0,
          "missing_controls": ["sbom", "dependency_scanning"]
        }
      ]
    }
    ```
