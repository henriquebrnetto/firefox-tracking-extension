# ThirdEye — Monitor de Privacidade

**Extensão para Firefox** desenvolvida como Avaliação Intermediária de Cybersegurança do Insper.

**Autores:** Henrique Bucci e Luigi Lopes

## O que é o ThirdEye?

ThirdEye é uma extensão para Firefox construída para monitorar, detectar e classificar ameaças invisíveis à privacidade enquanto você navega na web. Em tempo real, a extensão analisa o comportamento das páginas visitadas e apresenta um diagnóstico completo de forma didática e transparente.

### O que ela detecta e faz:

1. **Rastreadores e Terceiros** — intercepta requisições de rede, classificando-as entre rastreadores primários e de terceiros. Também lista todos os domínios de terceiros conectados, separando os neutros dos evasivos.
2. **Cookies e Supercookies** — classifica todos os cookies (1ª/3ª parte, sessão/persistente) detectados em cabeçalhos HTTP e realiza análise avançada de Supercookies usando a heurística de Entropia de Shannon.
3. **Impedimento de Impressão Digital (Canvas Fingerprinting)** — detecta no lado do cliente (via injeção de scripts) quando a página tenta contornar cookies para criar uma assinatura única do seu dispositivo usando `fillText` e `toDataURL`.
4. **Armazenamento HTML5 e Storage** — rastreia e avalia a quantidade de itens gravados localmente por localStorage, sessionStorage e bancos IndexedDB.
5. **Sincronismo de Cookies (Cookie Syncing)** — avalia requisições em cascata que tentam trocar identificadores silenciosamente entre redes de publicidade.
6. **Ameaças de Sequestro (Hijacking)** — identifica ameaças como injeção de iframes ocultos, uso de frameworks de ataque (como BeEF) e conexões não resolvidas direto a IPs externos.
7. **Score Dinâmico de Privacidade** — provê uma pontuação entre 0 e 100 com impacto medido por multiplicador de pesos relativos a cada infração encontrada, resultando em precisão contextual.
8. **Relatório Analítico com Exportação** — reúne o breakdown das requisições via painel visual no botão da barra de ferramentas, permitindo verificar e exportar em texto plano todo o histórico com 1 clique.
9. **Importação e Exportação de Listas** — gerencia de forma avançada domínios de bloqueio (Blocklist) e liberação (Whitelist) oferecendo uploads dinâmicos via `.txt`, `.csv` e `.json`.
10. **Nível de Sensibilidade Personalizável** — fornece ao usuário um controle de rigor de penalidades com três engrenagens (Relaxado, Equilibrado, Rigoroso) para o cálculo matemático da pontuação.
11. **Distribuição Visual de Categorias** — renderiza no painel principal um detalhamento gráfico e proporcional indicando a natureza predominante da ameaça (Propaganda, Métricas, Social, Fingerprint, etc).

## Como Instalar no Firefox

### Instalação Temporária (Desenvolvimento)

1. Abra seu navegador Firefox.
2. Digite `about:debugging` na barra de endereços (URL).
3. No painel à esquerda, clique em **"Este Firefox"** (ou "This Firefox").
4. Clique no botão **"Carregar extensão temporária..."** (ou "Load Temporary Add-on...").
5. Navegue até o diretório do repositório, abra a pasta `src/` e selecione o arquivo `manifest.json`.
6. O ícone ◉ do ThirdEye será afixado automaticamente no canto superior direito do seu navegador.

### Testando Importação de Listas

Para simular o ecossistema de importação/exportação de bloqueios dinâmicos:
1. Verifique que na raiz do projeto existe o arquivo `teste_importacao_bloqueio.json`. Esse arquivo contém uma array JSON com três domínios maliciosos fictícios para teste.
2. Clique no ◉ do ThirdEye inserido no Firefox, e no painel clique em **⚙ Configurações**.
3. Na seção "Lista de Bloqueio Personalizada", clique em **"⬆ Importar lista"**.
4. Selecione o arquivo `teste_importacao_bloqueio.json`. A extensão fará a ingestão e validação do JSON, e os domínios ficarão salvos e protegidos no `storage` persistente da extensão automaticamente.

## Arquitetura da Extensão

A estrutura interna utiliza base unificada (Vanilla JS puro) sem dependência externa, dividida de maneira modular:

```text
src/
├── manifest.json                     # Definições V2, permissões e setup
├── dados/
│   └── dominios_conhecidos.js        # Repositório imutável O(1) de mapeamentos
├── nucleo/
│   ├── monitor.js                    # Background Script (motor de auditoria webRequest)
│   └── inspetor.js                   # Content Script (interceptor client-side DOM/Window)
├── interface/
│   ├── painel/
│   │   ├── painel.html               # UI do Popup (Abas Visão Geral, Detalhes e Relatórios)
│   │   ├── painel.css                # Interface Dark GitHub-Friendly moderna
│   │   └── painel.js                 # Bridge de consumo e renderização do popup
│   └── ajustes/
│       ├── ajustes.html              # Interface de Configurações Avançadas
│       ├── ajustes.css               # Folha de estilo do backend options
│       └── ajustes.js                # Lógica de controle e manipulador de sensibilidade
└── icones/                           # Assets gráficos responsivos
```

## Referências e Metodologias Técnicas

- **[MDN: Anatomia de uma WebExtension](https://developer.mozilla.org/pt-BR/docs/Mozilla/Add-ons/WebExtensions/Anatomy_of_a_WebExtension) e [MDN: webRequest API](https://developer.mozilla.org/pt-BR/docs/Mozilla/Add-ons/WebExtensions/API/webRequest)**: Utilizados como documentação oficial para estruturar os `Background Scripts` e interceptar pacotes de rede via `browser.webRequest` (no arquivo `monitor.js`).
- **[Entropia de Shannon (Definição Matemática)](https://pt.wikipedia.org/wiki/Entropia_da_informa%C3%A7%C3%A3o)**: Lógica algorítmica reproduzida dentro do cálculo base de identificação de Supercookies de longa duração, calculando alta entropia de caracteres.
- **[BrowserLeaks: Canvas Fingerprinting](https://browserleaks.com/canvas)**: Nos apresentou aos métodos da API `toDataURL` e `fillText`. Utilizamos essas referências ativas para criar os injetores via Monkey Patching no `inspetor.js`.
- **[The Web Never Forgets: Tracking Mechanisms](https://securehomes.esat.kuleuven.be/~gacar/persistent/index.html)**: Documento teórico fundamental que explicou as lógicas de propagandas por Cookie Syncing cruzado que traduzimos no algoritmo de detecção de redirecionamento cascata.
- **[EasyList e EasyPrivacy](https://easylist.to/)**: Filtros de bloqueio do uBlock consumidos ativamente em nossa heurística de criação da base O(1) imutável em `dominios_conhecidos.js`.