# Arquitetura e Interface do Frontend 🎨🖥️

A interface do **Threat Command Center** foi desenvolvida sem frameworks complexos de JavaScript (como React, Angular ou Vue), apostando no paradigma **Vanilla JavaScript (JS Puro)**. Isto assegura desempenho máximo, sem o peso ou a latência associados à compilação de bibliotecas pesadas. 

A estilização visual combina folhas de estilo CSS3 puras com classes utilitárias do TailwindCSS no painel operacional, resultando num visual impactante e ultra-rápido.

---

## 📂 Organização de Ficheiros do Frontend

Com a reestruturação física do repositório, o frontend passou a separar rigidamente os ficheiros ativos de produção dos scripts de suporte de desenvolvimento:

### 1. Landing Page (Portal de Entrada)
- **`index.html`:** O portal estético de entrada. Projetado para captar a atenção do utilizador, exibe uma secção "Hero" animada, painéis de estatísticas dinâmicas e uma simulação de "Terminal Tático" conectada em tempo real ao radar de ameaças do backend.
- **`home.css`:** Contém toda a estilização e animações exclusivas da Landing Page. Define regras puristas de animações complexas (ex: rotação tridimensional de radares, pulsação de blips de geolocalização e gradientes de cores animadas).
- **`home.js`:** Gere as interações da página inicial, efetuando chamadas assíncronas assentes em Fetch API para alimentar as estatísticas globais reais e o feed simulado do terminal com dados obtidos da API do backend.

### 2. Dashboard Operacional (Painel Central)
- **`dashboard.html`:** O centro nervoso da plataforma operacional. Implementa um layout tático dividido em *Sidebar* de navegação e *Content Area*. Utiliza um paradigma de Single Page Application (SPA) nativa, onde cada módulo de inteligência reside numa tag `<section class="module-section">` que é exibida ou ocultada no DOM via lógica de controlo JS.
- **`style.css`:** Folha de estilos avançada que enriquece as classes básicas do TailwindCSS. Define animações de scrollbars personalizadas, efeitos de *glassmorphism* complexos, botões táticos de severidade (`.cyber-btn`, `.severity-badge`) e grelhas de dados customizadas.
- **`app.js`:** O motor tático que gere o dashboard. Trata a navegação entre secções, mantém o estado global ativo no cliente, efetua o polling de background jobs da API FastAPI, renderiza mapas de forma síncrona com `Leaflet.js` e faz a leitura Drag & Drop de manifestos de dependências arrastados para a área de upload.

### 3. Ferramentas do Desenvolvedor (Tucked Away)
- **`tools/`:** Subdiretório criado para acomodar os scripts utilitários em Python (`add_css_colors.py`, `fix_css.py`, `rewrite_index.py`, etc.) usados na fase de construção. Mantê-los isolados limpa a raiz do frontend, permitindo que apenas os ativos necessários para execução web fiquem expostos no servidor estático.

---

## 🕶️ O Design System: "Cyberpunk Minimalista"

A interface do **Threat Command Center** adota uma estética imersiva focada no contraste de alta visibilidade e na representação gráfica de criticidade sob um fundo permanentemente escuro (Dark Mode obrigatório). 

```text
┌────────────────────────────────────────────────────────────────────────┐
│  Estética de Interface: Tons de Fundo Noturnos & Neon Reativo          │
│                                                                        │
│  [Ciano/Teal]    Ações Principais, Sucesso e Estado do Scheduler       │
│  [Âmbar/Laranja] Alertas Intermédios, Supply Chain e Georreferência    │
│  [Rosa/Carmim]   Vulnerabilidades Graves, Alertas Críticos e NIS2 Gaps │
│  [Violeta/Roxo]  Inspeções de SBOM profundas e Monitorização Dark Web  │
└────────────────────────────────────────────────────────────────────────┘
```

### Paleta de Cores e Significado Tático

- **Ciano (`#06b6d4`) & Teal (`#14b8a6`):** Neutro tático. Representa o estado saudável das comunicações, o scheduler ativo em background e botões de ação principal.
- **Esmeralda (`#10b981`):** Sucesso e integridade. Indica que um módulo completou a pesquisa sem encontrar vulnerabilidades ou que um controlo NIS2 está devidamente implementado.
- **Âmbar (`#f59e0b`) & Laranja (`#f97316`):** Alerta de risco médio. Usado em vulnerabilidades moderadas, ameaças regionais geolocalizadas no mapa e erros leves de *typosquatting*.
- **Rosa Carmim (`#f43f5e`):** Crítico e perigoso. Identifica CVEs de impacto CVSS extremo (9.0+), caminhos de exploração direta no simulador de Attack Path e artigos de risco extremo no radar.
- **Violeta (`#a855f7`):** Varreduras profundas de IA e Dark Web. Associa-se a análises complexas (como SBOMs) e deteção de tráfego na rede anónima.

---

## ⚡ UX e Padrões de Interação do Utilizador

1.  **Glassmorphism Operacional (`.glass-card`):**
    Os painéis e menus laterais utilizam fundos semi-transparentes com desfoque de fundo reativo (`backdrop-filter: blur(12px)`) e bordas extremamente finas de cor branca-translúcida. Isto gera um efeito holográfico futurista sem degradar o desempenho gráfico.
2.  **Upload de Ficheiros Drag & Drop Dinâmico:**
    Os módulos SBOM e Supply Chain incorporam listeners HTML5 nativos que permitem arrastar diretamente ficheiros `package.json` ou `requirements.txt` para a área visual do browser. O processamento inicia instantaneamente via chamadas REST Multipart-Form sem recarregamentos visuais.
3.  **Transições Fluidas:**
    A navegação na SPA manipula a visibilidade de elementos com classes de transição de opacidade (`transition-all duration-300`). Isto assegura que a alternância entre módulos de inteligência seja suave, dando uma sensação de resposta instantânea de um painel de controlo integrado.
