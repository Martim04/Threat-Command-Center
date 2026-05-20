# Visão Geral do Projeto: Threat Command Center 📡🛡️

## 1. Introdução

O **Threat Command Center** é uma plataforma tática de cibersegurança e inteligência de ameaças de última geração. Projetado especificamente para equipas de operações de segurança e engenharia de resiliência, o sistema unifica feeds de inteligência aberta (OSINT), inventário de vulnerabilidades conhecidas (CVEs), conformidade com diretivas regulatórias europeias (NIS2), análise preventiva contra envenenamento de pacotes (Supply Chain Security) e diagramação automática de caminhos de exploração baseados no framework MITRE ATT&CK.

A plataforma distingue-se por uma interface imersiva de inspiração **cyberpunk minimalista**, com foco em alto contraste, visibilidade imediata de indicadores críticos e micro-animações dinâmicas que proporcionam uma experiência digna de um centro de comando militar moderno (SOC/NOC).

---

## 2. Arquitetura de Alto Nível

A plataforma assenta sobre um modelo de arquitetura **cliente-servidor assíncrono**, otimizado para latência ultra-baixa, simplicidade de implantação local (self-contained) e isolamento completo de responsabilidades:

```text
       ┌────────────────────────────────────────────────────────┐
       │               Interface do Utilizador                  │
       │     [Frontend - SPA Vanilla HTML5/CSS3/JavaScript]      │
       └───────────┬────────────────────────────────┬───────────┘
                   │                                │
        Chamadas assíncronas (Fetch)       Renderização do Mapa
                   │                                │
                   ▼                                ▼
       ┌────────────────────────────────────────────────────────┐
       │                 API REST Assíncrona                    │
       │              [Backend - Python FastAPI]                │
       └───────────┬────────────────────────────────┬───────────┘
                   │                                │
           Queries SQLite                   Scraping & Consultas APIs
                   │                                │
                   ▼                                ▼
┌──────────────────────────────┐        ┌──────────────────────────────┐
│        Base de Dados         │        │    Integrações Externas      │
│     [SQLite Local]           │        │   - Google OSV API           │
│   - Histórico de Scans       │        │   - NIST NVD API             │
│   - Configurações da Stack   │        │   - Feeds RSS (CISA, etc.)   │
│   - Feed Processado          │        │   - Leaflet.js Geolocation   │
└──────────────────────────────┘        └──────────────────────────────┘
```

### Componentes Principais

- **Camada de Apresentação (Frontend):**
  Implementada como uma **Single Page Application (SPA)** nativa, recorrendo a manipulação dinâmica de DOM via JavaScript Vanilla. Evita o overhead de frameworks pesados (como React, Angular ou Vue), garantindo tempos de renderização instantâneos e interações táteis fluidas. Combina CSS purista com classes utilitárias do TailwindCSS para alcançar o visual cyberpunk imersivo.

- **Camada de Lógica de Negócio (Backend):**
  Alimentada por **FastAPI (Python)**, que providencia execução assíncrona nativa de alta performance, ideal para lidar com múltiplas requisições paralelas e tarefas de rede simultâneas (ex: scraping concorrente de RSS feeds e chamadas assíncronas a APIs de terceiros).

- **Camada de Persistência (Base de Dados):**
  Utiliza o **SQLite**, uma base de dados leve baseada em ficheiro (`threat_center.db`), dispensando a necessidade de configurar infraestruturas complexas ou servidores adicionais. Acesso e escrita são otimizados diretamente através de Python nativo de alta concorrência em `database.py`.

---

## 3. Ecossistema Tecnológico

| Camada | Tecnologia | Justificação Estratégica |
| :--- | :--- | :--- |
| **Frontend Core** | HTML5 / CSS3 / Vanilla JS | Controlo absoluto sobre o ciclo de renderização, micro-animações ricas sem dependências externas, flexibilidade no desenho da UI. |
| **Estilização** | Tailwind CSS + Custom CSS | Agilidade no desenvolvimento com classes utilitárias rápidas aliadas a gradientes complexos, efeitos glassmorphism e brilhos personalizados em CSS nativo. |
| **Visualizações** | Leaflet.js | Biblioteca de mapas extremamente leve e de alta performance para representação geográfica interativa das ameaças mundiais. |
| **Backend API** | FastAPI (Python) | Desempenho assíncrono ao nível de Node.js/Go, validação automática de dados via Pydantic e geração nativa de documentação OpenAPI/Swagger. |
| **Armazenamento** | SQLite | Armazenamento relacional ultra-rápido contido num único ficheiro local, facilitando a portabilidade e permitindo cópias de segurança instantâneas. |

---

## 4. Público-Alvo e Vetores de Valor

O **Threat Command Center** foi concebido para endereçar as necessidades de três perfis cruciais em qualquer infraestrutura de defesa tecnológica:

*   **Analistas de SOC (Security Operations Center):**
    Fornece visibilidade holística e em tempo real sobre campanhas de exploração globais através do **OSINT Radar** e do **Threat Map** georreferenciado, permitindo identificar picos de ameaças em segundos.

*   **Engenheiros de AppSec & DevSecOps:**
    Automatiza a inspeção de manifestos SBOM e rastreia vulnerabilidades ativas na cadeia de fornecimento de bibliotecas externas (NPM, PyPI, Maven, Cargo, Go) recorrendo ao **SBOM Scanner** e **Supply Chain Detector**.

*   **CISOs & Administradores de TI (Compliance & Risk):**
    Facilita a análise da postura de segurança face à legislação europeia de cibersegurança **NIS2**, gerando roadmaps de remediação baseados na stack tecnológica ativa da empresa e nas vulnerabilidades reais detetadas no ambiente.
