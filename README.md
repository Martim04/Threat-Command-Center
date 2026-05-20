# Threat Command Center 📡🛡️

O **Threat Command Center** é uma plataforma centralizada de inteligência cibernética projetada para profissionais de segurança (analistas de SOC/NOC, engenheiros de DevSecOps, CISOs). Agrega inteligência de fontes públicas (OSINT), monitorização de vulnerabilidades (CVEs), análise de conformidade legal (NIS2), deteção de riscos na cadeia de fornecimento (SBOM/Supply Chain) e simulação de caminhos de ataque (MITRE ATT&CK).

Tudo isto é apresentado através de uma interface de utilizador imersiva, dinâmica e responsiva de inspiração **cyberpunk**, otimizada para centros de operações táticas.

---

## 📂 Estrutura do Repositório

O projeto adota uma arquitetura limpa e modular de fácil navegação:

```text
CIBER_APP/
├── backend/                  # Servidor API FastAPI (Python 3.9+)
│   ├── .env.example          # Exemplo de configuração de variáveis de ambiente
│   ├── main.py               # Ponto de entrada e rotas da API REST (24 endpoints)
│   ├── database.py           # Abstração da base de dados SQLite
│   ├── scheduler.py          # Automação de jobs periódicos em background
│   ├── logger.py             # Configuração central de logging
│   ├── radar.py              # Agregação OSINT via feeds RSS assíncronos
│   ├── sbom.py               # Mapeador SBOM via Google OSV API
│   ├── supply_chain.py       # Deteção de Typosquatting/Dependency Confusion
│   ├── attack_path.py        # Simulação e cálculo de caminhos de ataque
│   ├── compliance.py         # Motor de análise de lacunas (Gap Analyzer) NIS2
│   ├── scanner.py            # Motor de scans a vulnerabilidades
│   └── requirements.txt      # Dependências Python
│
├── frontend/                 # Interface do Utilizador (Vanilla JS + CSS3 + Tailwind)
│   ├── index.html            # Landing Page interativa com terminal em tempo real
│   ├── dashboard.html        # Painel central da plataforma com layout multi-módulos
│   ├── home.css              # Estilos e animações da Landing Page
│   ├── home.js               # Lógica de loading de stats e feed na Landing Page
│   ├── style.css             # Estilos personalizados, glassmorphism e utilitários do Dashboard
│   ├── app.js                # Core JS, roteamento SPA, mapa Leaflet e Drag & Drop
│   └── tools/                # Scripts utilitários de desenvolvimento (Python)
│       ├── add_css_colors.py
│       ├── fix_css.py
│       ├── fix_css2.py
│       ├── fix_final.py
│       └── rewrite_index.py
│
└── documentacao/             # Documentação Detalhada do Projeto
    ├── 1_visao_geral.md      # Visão geral, arquitetura e público-alvo
    ├── 2_backend_api.md      # Detalhes das rotas REST e responsabilidades do backend
    ├── 3_frontend_ui.md      # Arquitetura do frontend, design system e UX/UI
    ├── 4_modulos.md          # Funcionamento detalhado dos 9 módulos de inteligência
    └── 5_guia_instalacao.md  # Instalação, requisitos, configuração e troubleshooting
```

---

## ⚡ Guia Rápido de Execução

### 1. Requisitos Prévios
- Python 3.9+ instalado no seu sistema.
- Um terminal de comandos moderno (Bash, Zsh ou PowerShell).

### 2. Configurar e Iniciar o Backend
Navegue até à pasta `backend/` e execute os seguintes passos:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # No Windows use: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # Configure o seu .env se necessário
uvicorn main:app --reload --port 8000
```
O backend ficará disponível em `http://localhost:8000`. A documentação interativaSwagger/OpenAPI pode ser acedida em `http://localhost:8000/docs`.

### 3. Iniciar o Frontend
Navegue até à pasta `frontend/` num novo terminal e sirva os ficheiros estáticos:
```bash
cd frontend
python -m http.server 3000
```
Abra o seu navegador em `http://localhost:3000`.

---

## 🛡️ Os 9 Módulos de Inteligência

1. **Global OSINT Radar**: Agrega e processa feeds RSS em tempo real, extraindo automaticamente menções a CVEs por regex.
2. **SBOM Scanner**: Importa manifestos de dependências (`package.json`, `requirements.txt`, etc.) via Drag & Drop e identifica vulnerabilidades na base do Google OSV.
3. **Stack CVE Tracker**: Monitoriza a infraestrutura tecnológica registada contra a base da NIST NVD API.
4. **Global Threat Map**: Renderiza localizações de incidentes num mapa global interativo (`Leaflet.js`).
5. **Dark Web Monitor**: Faz rastreio de credenciais e domínios expostos em bases de leaks conhecidas e fóruns.
6. **Supply Chain Detector**: Analisa manifestos em busca de envenenamento de dependências (*typosquatting*).
7. **Attack Path Visualizer**: Desenha caminhos lógicos de invasão baseados em técnicas TTP do framework MITRE ATT&CK.
8. **NIS2 Compliance Analyzer**: Mede a conformidade com a diretiva europeia NIS2 e gera relatórios de gap análise e roadmaps.
9. **Auto Scheduler**: Controla e executa tarefas periódicas agendadas em segundo plano.

---

## 📖 Documentação Detalhada

Para informações aprofundadas sobre cada camada do sistema, consulte a documentação dedicada na pasta `documentacao/`:

- [1. Visão Geral do Projeto](file:///Users/martimaraujo/Desktop/CIBER_APP/documentacao/1_visao_geral.md)
- [2. Detalhes de Backend & APIs](file:///Users/martimaraujo/Desktop/CIBER_APP/documentacao/2_backend_api.md)
- [3. Arquitetura & UX/UI de Frontend](file:///Users/martimaraujo/Desktop/CIBER_APP/documentacao/3_frontend_ui.md)
- [4. Detalhes Técnicos dos Módulos](file:///Users/martimaraujo/Desktop/CIBER_APP/documentacao/4_modulos.md)
- [5. Manual Completo de Instalação](file:///Users/martimaraujo/Desktop/CIBER_APP/documentacao/5_guia_instalacao.md)
