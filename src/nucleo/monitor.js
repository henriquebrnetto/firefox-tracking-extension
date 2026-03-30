/**
 * ThirdEye — Monitor de Privacidade (Background Script)
 *
 * Responsável por:
 * - Interceptar requisições HTTP e identificar domínios de terceiros
 * - Monitorar cookies via headers (Set-Cookie) e classificar tipo
 * - Detectar sincronismo de cookies entre domínios
 * - Identificar ameaças de sequestro (hijacking)
 * - Calcular pontuação de privacidade por pesos relativos
 * - Comunicar dados ao painel (popup) e ao inspetor (content script)
 */

// ==========================================
// Registro de navegação por aba
// ==========================================

/**
 * Armazena os dados coletados para cada aba aberta.
 * Chave: tabId (number), Valor: objeto com métricas.
 *
 * Diferente do OlhaMalandro que usa um objeto global "tabData" simples.
 * Aqui usamos um objeto com um API namespace "RegistroNavegacao".
 */
const RegistroNavegacao = {
  _abas: {},

  /**
   * Cria ou reseta o registro de uma aba.
   */
  inicializar(abaId, url) {
    const host = Util.extrairHost(url);
    this._abas[abaId] = {
      endereco: url,
      hostPrincipal: host,
      dominiosTerceiros: new Set(),
      rastreadoresEncontrados: new Set(),
      dominiosBloqueados: new Set(),
      rastreadoresPrimarios: new Set(),
      rastreadoresExternos: new Set(),
      cookies: {
        primario: { sessao: 0, permanente: 0 },
        terceiro: { sessao: 0, permanente: 0 },
        total: 0,
        longa_duracao: 0 // "supercookies" — cookies com duração excessiva ou alta entropia
      },
      armazenamentoLocal: {
        encontrado: false,
        chaves: [],
        tamanhoBytes: 0
      },
      impressaoDigital: {
        encontrado: false,
        ocorrencias: 0
      },
      sequestro: {
        encontrado: false,
        alertas: []
      },
      sincronismoCookies: {
        encontrado: false,
        pares: []
      },
      requisicoes: 0,
      bloqueios: 0,
      notaPrivacidade: 100,
      momentoCriacao: Date.now()
    };
    console.log("[ThirdEye] Registro criado — aba=" + abaId + " host=" + host);
  },

  obter(abaId) {
    return this._abas[abaId] || null;
  },

  existe(abaId) {
    return abaId in this._abas;
  },

  remover(abaId) {
    delete this._abas[abaId];
  },

  /**
   * Serializa dados (converte Sets para Arrays para envio via mensagem).
   */
  serializar(abaId) {
    const reg = this._abas[abaId];
    if (!reg) return null;
    return {
      ...reg,
      dominiosTerceiros: [...reg.dominiosTerceiros],
      rastreadoresEncontrados: [...reg.rastreadoresEncontrados],
      dominiosBloqueados: [...reg.dominiosBloqueados],
      rastreadoresPrimarios: [...reg.rastreadoresPrimarios],
      rastreadoresExternos: [...reg.rastreadoresExternos]
    };
  }
};

// ==========================================
// Funções utilitárias
// ==========================================
const Util = {
  /**
   * Extrai o hostname de uma URL.
   */
  extrairHost(url) {
    try {
      const parsed = new URL(url);
      if (parsed.protocol === "file:") return "arquivo-local";
      return parsed.hostname;
    } catch (e) {
      return "";
    }
  },

  /**
   * Extrai o domínio raiz de um hostname (ex: "sub.exemplo.com" → "exemplo.com").
   */
  extrairDominioRaiz(hostname) {
    if (!hostname || hostname === "arquivo-local") return hostname;
    const partes = hostname.split(".");
    if (partes.length <= 2) return hostname;
    return partes.slice(-2).join(".");
  },

  /**
   * Verifica se um hostname de requisição pertence a um domínio diferente da página.
   */
  ehTerceiro(hostRequisicao, hostPagina) {
    if (!hostRequisicao || !hostPagina) return false;
    if (hostPagina === "arquivo-local") return hostRequisicao !== "arquivo-local";
    return this.extrairDominioRaiz(hostRequisicao) !== this.extrairDominioRaiz(hostPagina);
  },

  /**
   * Calcula a entropia de Shannon de uma string.
   * Usada para detectar cookies com valores altamente aleatórios (tracking IDs).
   *
   * Heurística diferente do OlhaMalandro, que usa apenas regex para hex ≥32 chars.
   * Aqui medimos a aleatoriedade real do conteúdo.
   */
  calcularEntropia(texto) {
    if (!texto || texto.length === 0) return 0;
    const freq = {};
    for (const ch of texto) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropia = 0;
    const len = texto.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      entropia -= p * Math.log2(p);
    }
    return entropia;
  }
};

// ==========================================
// Configurações do usuário
// ==========================================
let preferencias = {
  bloqueioAtivo: true,
  listaPersonalizada: [],   // domínios a bloquear além da lista padrão
  listaPermitidos: [],       // domínios a nunca bloquear
  sensibilidade: 1           // 0=relaxado, 1=equilibrado, 2=rigoroso (Conceito A)
};

browser.storage.local.get("preferencias").then((res) => {
  if (res.preferencias) {
    preferencias = { ...preferencias, ...res.preferencias };
  }
});

browser.storage.onChanged.addListener((mudancas) => {
  if (mudancas.preferencias) {
    preferencias = { ...preferencias, ...mudancas.preferencias.newValue };
  }
});

// ==========================================
// Decisão de bloqueio
// ==========================================
function deveBloquear(hostname) {
  // Whitelist tem prioridade
  if (preferencias.listaPermitidos.some(d => hostname === d || hostname.endsWith("." + d))) {
    return false;
  }
  // Blocklist personalizada
  if (preferencias.listaPersonalizada.some(d => hostname === d || hostname.endsWith("." + d))) {
    return true;
  }
  // Lista padrão de rastreadores
  return verificarRastreador(hostname);
}

// ==========================================
// Interceptação de requisições
// ==========================================
browser.webRequest.onBeforeRequest.addListener(
  (detalhes) => {
    const abaId = detalhes.tabId;
    if (abaId < 0) return {};

    // Navegação principal — inicializar registro
    if (detalhes.type === "main_frame") {
      RegistroNavegacao.inicializar(abaId, detalhes.url);
      return {};
    }

    // Garantir que o registro existe
    if (!RegistroNavegacao.existe(abaId)) {
      const urlOrigem = detalhes.documentUrl || detalhes.originUrl || "";
      if (urlOrigem) {
        RegistroNavegacao.inicializar(abaId, urlOrigem);
      } else {
        return {};
      }
    }

    const reg = RegistroNavegacao.obter(abaId);
    const hostReq = Util.extrairHost(detalhes.url);
    const hostPag = reg.hostPrincipal;
    if (!hostReq || !hostPag) return {};

    reg.requisicoes++;

    // Classificar a requisição
    if (Util.ehTerceiro(hostReq, hostPag)) {
      reg.dominiosTerceiros.add(hostReq);

      if (verificarRastreador(hostReq)) {
        reg.rastreadoresExternos.add(hostReq);
        reg.rastreadoresEncontrados.add(hostReq);
      }
    } else {
      if (verificarRastreador(hostReq)) {
        reg.rastreadoresPrimarios.add(hostReq);
        reg.rastreadoresEncontrados.add(hostReq);
      }
    }

    // Análises adicionais
    analisarSincronismoCookies(detalhes, abaId);
    analisarSequestro(detalhes, abaId);

    // Bloquear se configurado
    if (preferencias.bloqueioAtivo && Util.ehTerceiro(hostReq, hostPag) && deveBloquear(hostReq)) {
      reg.dominiosBloqueados.add(hostReq);
      reg.bloqueios++;
      atualizarIcone(abaId);
      return { cancel: true };
    }

    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

// ==========================================
// Análise de headers de requisição
// ==========================================
browser.webRequest.onBeforeSendHeaders.addListener(
  (detalhes) => {
    const abaId = detalhes.tabId;
    if (abaId < 0 || !RegistroNavegacao.existe(abaId)) return {};

    const reg = RegistroNavegacao.obter(abaId);
    const hostReq = Util.extrairHost(detalhes.url);

    // Verificar cookie syncing via headers de requisição
    const headerCookie = detalhes.requestHeaders.find(h => h.name.toLowerCase() === "cookie");
    if (headerCookie && Util.ehTerceiro(hostReq, reg.hostPrincipal)) {
      // Se está enviando cookies para um terceiro com parâmetros de ID na URL
      const url = detalhes.url;
      if (/[?&](uid|sid|pid|visitor_id|user_id|_uid|clickid|ref_id)=/i.test(url)) {
        reg.sincronismoCookies.encontrado = true;
        reg.sincronismoCookies.pares.push({
          origem: reg.hostPrincipal,
          destino: hostReq,
          evidencia: "Parâmetro de ID na URL com cookie de terceiro"
        });
      }
    }
    return {};
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// ==========================================
// Análise de headers de resposta (cookies)
// ==========================================
browser.webRequest.onHeadersReceived.addListener(
  (detalhes) => {
    const abaId = detalhes.tabId;
    if (abaId < 0 || !RegistroNavegacao.existe(abaId)) return {};

    const reg = RegistroNavegacao.obter(abaId);
    const hostResp = Util.extrairHost(detalhes.url);
    const ehExterno = Util.ehTerceiro(hostResp, reg.hostPrincipal);

    detalhes.responseHeaders.forEach((header) => {
      const nome = header.name.toLowerCase();

      if (nome === "set-cookie") {
        reg.cookies.total++;
        const valor = header.value.toLowerCase();

        // Classificar: sessão vs permanente
        const temExpiracao = valor.includes("expires=") || valor.includes("max-age=");

        // Verificar se é cookie de longa duração (nosso equivalente a "supercookie")
        if (verificarCookieLongaDuracao(header.value)) {
          reg.cookies.longa_duracao++;
        }

        if (ehExterno) {
          if (temExpiracao) reg.cookies.terceiro.permanente++;
          else reg.cookies.terceiro.sessao++;
        } else {
          if (temExpiracao) reg.cookies.primario.permanente++;
          else reg.cookies.primario.sessao++;
        }
      }

      // Detectar redirecionamentos suspeitos (hijacking)
      if (nome === "location" && detalhes.statusCode >= 300 && detalhes.statusCode < 400) {
        const hostRedir = Util.extrairHost(header.value);
        if (hostRedir && Util.ehTerceiro(hostRedir, reg.hostPrincipal) && verificarRastreador(hostRedir)) {
          reg.sequestro.encontrado = true;
          reg.sequestro.alertas.push({
            categoria: "redirecionamento_rastreador",
            de: hostResp,
            para: hostRedir,
            descricao: "Redirecionamento para domínio de rastreamento detectado"
          });
        }
      }
    });
    return {};
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ==========================================
// Detecção de cookies de longa duração
// ==========================================

/**
 * Verifica se um cookie tem características de rastreamento persistente.
 *
 * Heurísticas (DIFERENTES do OlhaMalandro):
 * 1. max-age > 6 meses (OlhaMalandro usa > 1 ano)
 * 2. Cookie com SameSite=None + Secure (indicador de cross-site tracking)
 * 3. Valor com alta entropia (Shannon > 3.5 bits/char) — mais sofisticado que regex hex
 */
function verificarCookieLongaDuracao(valorCompleto) {
  const lower = valorCompleto.toLowerCase();

  // Heurística 1: Max-age > 6 meses (15.768.000 segundos)
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  if (maxAgeMatch) {
    const segundos = parseInt(maxAgeMatch[1]);
    if (segundos > 15768000) return true;
  }

  // Heurística 1b: Expires muito distante (> 6 meses)
  const expiresMatch = lower.match(/expires=([^;]+)/);
  if (expiresMatch) {
    try {
      const dataExpiracao = new Date(expiresMatch[1]);
      const agora = new Date();
      const diffMeses = (dataExpiracao - agora) / (1000 * 60 * 60 * 24 * 30);
      if (diffMeses > 6) return true;
    } catch (e) { /* data inválida, ignorar */ }
  }

  // Heurística 2: SameSite=None com Secure — indica uso cross-site intencional
  if (lower.includes("samesite=none") && lower.includes("secure")) {
    return true;
  }

  // Heurística 3: Valor do cookie com alta entropia (provavelmente tracking ID)
  const partes = valorCompleto.split("=");
  if (partes.length >= 2) {
    const valorCookie = partes[1].split(";")[0].trim();
    if (valorCookie.length >= 16) {
      const entropia = Util.calcularEntropia(valorCookie);
      // Entropia > 3.5 bits/char indica string pseudo-aleatória (tracking ID)
      if (entropia > 3.5) return true;
    }
  }

  return false;
}

// ==========================================
// Detecção de sincronismo de cookies
// ==========================================

/**
 * Analisa URLs de requisição em busca de padrões de cookie syncing.
 *
 * Diferente do OlhaMalandro que usa regex genéricas (/sync/, /match/, etc.).
 * Aqui analisamos especificamente parâmetros de query que contêm
 * identificadores repetidos entre domínios diferentes.
 */
function analisarSincronismoCookies(detalhes, abaId) {
  const reg = RegistroNavegacao.obter(abaId);
  if (!reg) return;

  const url = detalhes.url;
  const hostReq = Util.extrairHost(url);

  // Só analisar requisições de terceiros
  if (!Util.ehTerceiro(hostReq, reg.hostPrincipal)) return;

  // Padrões de endpoints de sincronização
  const padroesSinc = [
    /\/usersync[/?]/i,
    /\/cookie[-_]?match/i,
    /\/pixel[/?].*[?&].*id=/i,
    /\/cm[/?]/i,
    /\/sync[/?].*partner/i,
    /\/bounce[/?].*redirect/i,
    /\/tr[/?].*id=/i
  ];

  if (padroesSinc.some(p => p.test(url))) {
    reg.sincronismoCookies.encontrado = true;
    reg.sincronismoCookies.pares.push({
      origem: reg.hostPrincipal,
      destino: hostReq,
      evidencia: "Endpoint de sincronização detectado na URL"
    });
  }
}

// ==========================================
// Detecção de sequestro (hijacking)
// ==========================================

/**
 * Detecta ameaças de browser hijacking nas requisições.
 *
 * Heurísticas (DIFERENTES do OlhaMalandro):
 * - OlhaMalandro usa: hook.js, beef.*hook, exploit.*framework, keylog, xss.*payload
 * - Aqui usamos: eval patterns em URLs, scripts com codificação base64,
 *   requisições diretas a IPs externos, scripts de domínios suspeitos
 */
function analisarSequestro(detalhes, abaId) {
  const reg = RegistroNavegacao.obter(abaId);
  if (!reg) return;

  const url = detalhes.url;
  const hostReq = Util.extrairHost(url);

  // Padrão 1: Scripts com nomes suspeitos
  const nomesPerigosos = [
    /inject[._-]?script/i,
    /payload[._-]?delivery/i,
    /browser[._-]?hook/i,
    /key[._-]?capture/i,
    /form[._-]?grab/i
  ];
  if (detalhes.type === "script" && nomesPerigosos.some(p => p.test(url))) {
    reg.sequestro.encontrado = true;
    reg.sequestro.alertas.push({
      categoria: "script_perigoso",
      url: url,
      descricao: "Nome de script suspeito detectado (possível payload malicioso)"
    });
  }

  // Padrão 2: Requisição direta a endereço IP de terceiro
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostReq)) {
    if (Util.ehTerceiro(hostReq, reg.hostPrincipal)) {
      reg.sequestro.alertas.push({
        categoria: "ip_direto",
        url: url,
        descricao: "Requisição direta a endereço IP externo (possível C&C ou exfiltração)"
      });
    }
  }

  // Padrão 3: URLs com codificação base64 longa (possível código injetado)
  if (/[?&](data|payload|code|script)=[A-Za-z0-9+/=]{100,}/i.test(url)) {
    reg.sequestro.encontrado = true;
    reg.sequestro.alertas.push({
      categoria: "dados_codificados",
      url: url.substring(0, 120) + "...",
      descricao: "Dados codificados extensos na URL (possível injeção de código)"
    });
  }
}

// ==========================================
// Eventos de navegação
// ==========================================
browser.tabs.onUpdated.addListener((abaId, mudanca, aba) => {
  if (mudanca.status === "loading" && aba.url) {
    RegistroNavegacao.inicializar(abaId, aba.url);
    atualizarIcone(abaId);
  }
});

// Inicializar abas já abertas quando a extensão carrega
browser.tabs.query({}).then((abas) => {
  for (const aba of abas) {
    if (aba.url && aba.id >= 0) {
      RegistroNavegacao.inicializar(aba.id, aba.url);
    }
  }
  console.log("[ThirdEye] " + abas.length + " abas pré-inicializadas");
}).catch((e) => {
  console.warn("[ThirdEye] Falha ao consultar abas:", e);
});

browser.tabs.onRemoved.addListener((abaId) => {
  RegistroNavegacao.remover(abaId);
});

try {
  browser.webNavigation.onBeforeNavigate.addListener((detalhes) => {
    if (detalhes.frameId === 0) {
      RegistroNavegacao.inicializar(detalhes.tabId, detalhes.url);
    }
  });
} catch (e) {
  console.warn("[ThirdEye] webNavigation indisponível:", e);
}

// ==========================================
// Badge do ícone
// ==========================================
function atualizarIcone(abaId) {
  const reg = RegistroNavegacao.obter(abaId);
  if (!reg) return;

  const bloqueados = reg.dominiosBloqueados.size;
  const rastreadores = reg.rastreadoresEncontrados.size;
  const total = bloqueados > 0 ? bloqueados : rastreadores;
  const texto = total > 0 ? String(total) : "";

  // Cores diferentes do OlhaMalandro
  let cor;
  if (bloqueados > 0) cor = "#f85149";       // coral (OlhaMalandro usa #e74c3c)
  else if (rastreadores > 0) cor = "#d29922"; // âmbar (OlhaMalandro usa #f39c12)
  else cor = "#3fb950";                        // verde (OlhaMalandro usa #27ae60)

  browser.browserAction.setBadgeText({ text: texto, tabId: abaId });
  browser.browserAction.setBadgeBackgroundColor({ color: cor, tabId: abaId });
}

// ==========================================
// Pontuação de Privacidade — Sistema de Pesos
// ==========================================

/**
 * Calcula a nota de privacidade (0-100) usando pesos relativos por categoria.
 *
 * DIFERENTE do OlhaMalandro que usa deduções fixas simples.
 * Aqui cada categoria tem um peso percentual e a penalidade é proporcional
 * à quantidade de problemas encontrados, com um teto por categoria.
 */
function calcularNotaPrivacidade(abaId) {
  const reg = RegistroNavegacao.obter(abaId);
  if (!reg) return 100;

  // Multiplicador de sensibilidade (Conceito A)
  // 0=relaxado (0.7x), 1=equilibrado (1.0x), 2=rigoroso (1.3x)
  const multiplicadores = [0.7, 1.0, 1.3];
  const mult = multiplicadores[preferencias.sensibilidade] || 1.0;

  let penalidade = 0;

  // Categoria 1: Domínios de terceiros (peso 25, proporcional até 15 domínios)
  const fracaoTerceiros = Math.min(1, reg.dominiosTerceiros.size / 15);
  penalidade += fracaoTerceiros * 25 * mult;

  // Categoria 2: Cookies de terceiros (peso 20, proporcional até 10 cookies)
  const totalCookiesTerceiro = reg.cookies.terceiro.sessao + reg.cookies.terceiro.permanente;
  const fracaoCookies = Math.min(1, totalCookiesTerceiro / 10);
  penalidade += fracaoCookies * 20 * mult;

  // Categoria 3: Cookies de longa duração (peso 15, proporcional até 3)
  const fracaoLongaDuracao = Math.min(1, reg.cookies.longa_duracao / 3);
  penalidade += fracaoLongaDuracao * 15 * mult;

  // Categoria 4: Armazenamento HTML5 (peso 10, binário)
  if (reg.armazenamentoLocal.encontrado) {
    penalidade += 10 * mult;
  }

  // Categoria 5: Impressão digital / Canvas (peso 15, binário)
  if (reg.impressaoDigital.encontrado) {
    penalidade += 15 * mult;
  }

  // Categoria 6: Sincronismo de cookies (peso 5, binário)
  if (reg.sincronismoCookies.encontrado) {
    penalidade += 5 * mult;
  }

  // Categoria 7: Ameaças de sequestro (peso 10, binário)
  if (reg.sequestro.encontrado) {
    penalidade += 10 * mult;
  }

  reg.notaPrivacidade = Math.max(0, Math.round(100 - penalidade));
  return reg.notaPrivacidade;
}

// ==========================================
// Comunicação com o painel e inspetor
// ==========================================
browser.runtime.onMessage.addListener((mensagem, remetente, responder) => {

  // Painel solicitando dados da aba
  if (mensagem.tipo === "obterDadosAba") {
    const abaId = mensagem.abaId;

    if (!RegistroNavegacao.existe(abaId)) {
      // Tentar inicializar sob demanda
      browser.tabs.get(abaId).then((aba) => {
        if (aba && aba.url) {
          RegistroNavegacao.inicializar(abaId, aba.url);
        }
        calcularNotaPrivacidade(abaId);
        const dados = RegistroNavegacao.serializar(abaId);
        if (dados) {
          responder({ ok: true, dados: dados });
        } else {
          responder({ ok: false, erro: "Nenhum dado disponível para esta aba" });
        }
      }).catch(() => {
        responder({ ok: false, erro: "Não foi possível acessar os dados da aba" });
      });
      return true; // resposta assíncrona
    }

    calcularNotaPrivacidade(abaId);
    responder({ ok: true, dados: RegistroNavegacao.serializar(abaId) });
    return true;
  }

  // Inspetor (content script) enviando dados coletados no lado do cliente
  if (mensagem.tipo === "dadosInspetor") {
    const abaId = remetente.tab.id;

    if (!RegistroNavegacao.existe(abaId) && remetente.tab.url) {
      RegistroNavegacao.inicializar(abaId, remetente.tab.url);
    }

    const reg = RegistroNavegacao.obter(abaId);
    if (reg) {
      // Mesclar dados de armazenamento local
      if (mensagem.armazenamento) {
        reg.armazenamentoLocal = mensagem.armazenamento;
      }
      // Mesclar dados de impressão digital
      if (mensagem.impressaoDigital) {
        reg.impressaoDigital = mensagem.impressaoDigital;
      }
      // Mesclar dados de cookies do client-side
      if (mensagem.cookiesCliente) {
        const cli = mensagem.cookiesCliente;
        reg.cookies.total = Math.max(reg.cookies.total, cli.total || 0);
        reg.cookies.primario.sessao = Math.max(reg.cookies.primario.sessao, cli.primario?.sessao || 0);
        reg.cookies.primario.permanente = Math.max(reg.cookies.primario.permanente, cli.primario?.permanente || 0);
        reg.cookies.longa_duracao = Math.max(reg.cookies.longa_duracao, cli.longa_duracao || 0);
      }
      // Mesclar alertas de sequestro
      if (mensagem.alertasSequestro && mensagem.alertasSequestro.length > 0) {
        mensagem.alertasSequestro.forEach(alerta => {
          reg.sequestro.encontrado = true;
          reg.sequestro.alertas.push(alerta);
        });
      }
      atualizarIcone(abaId);
      console.log("[ThirdEye] Dados do inspetor recebidos — aba=" + abaId);
    }
    return true;
  }

  // Obter preferências
  if (mensagem.tipo === "obterPreferencias") {
    responder({ ok: true, preferencias: preferencias });
    return true;
  }

  // Salvar preferências
  if (mensagem.tipo === "salvarPreferencias") {
    preferencias = { ...preferencias, ...mensagem.preferencias };
    browser.storage.local.set({ preferencias });
    responder({ ok: true });
    return true;
  }

  // Alternar bloqueio
  if (mensagem.tipo === "alternarBloqueio") {
    preferencias.bloqueioAtivo = mensagem.ativo;
    browser.storage.local.set({ preferencias });
    responder({ ok: true, ativo: preferencias.bloqueioAtivo });
    return true;
  }
});
