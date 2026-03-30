/**
 * ThirdEye — Lógica do Painel (Popup)
 *
 * Gerencia a interface, carrega dados do monitor (background),
 * e renderiza as informações coletadas.
 *
 * Diferenças em relação ao OlhaMalandro:
 * - Navegação por abas (não accordion)
 * - Barra horizontal de score (não SVG circular)
 * - Nomes de funções, IDs e mensagens completamente diferentes
 */

document.addEventListener("DOMContentLoaded", () => {
  // ==========================================
  // Inicialização
  // ==========================================
  configurarAbas();
  configurarBloqueio();
  configurarBotoes();
  carregarDados();

  // Referência aos dados para uso em renderização do relatório e exportação
  let _dadosAtuais = null;

  // ==========================================
  // Carregar dados da aba ativa
  // ==========================================
  function carregarDados() {
    browser.tabs.query({ active: true, currentWindow: true }).then((abas) => {
      if (!abas[0]) return;
      const aba = abas[0];

      // Mostrar hostname
      try {
        document.getElementById("infoSite").textContent = new URL(aba.url).hostname || aba.url;
      } catch (e) {
        document.getElementById("infoSite").textContent = aba.url;
      }

      // Solicitar dados ao monitor (background)
      browser.runtime.sendMessage({
        tipo: "obterDadosAba",
        abaId: aba.id
      }).then((resposta) => {
        if (resposta && resposta.ok) {
          renderizarTudo(resposta.dados);
        } else {
          document.getElementById("notaDescricao").textContent =
            "Navegue para uma página web para iniciar a análise.";
        }
      }).catch(() => {
        document.getElementById("notaDescricao").textContent =
          "Navegue para uma página web para iniciar a análise.";
      });
    });
  }

  // ==========================================
  // Renderizar todos os dados
  // ==========================================
  function renderizarTudo(dados) {
    _dadosAtuais = dados;

    renderizarNota(dados.notaPrivacidade);

    // Contadores
    document.getElementById("numTerceiros").textContent = dados.dominiosTerceiros.length;
    document.getElementById("numRastreadores").textContent = dados.rastreadoresEncontrados.length;
    document.getElementById("numBloqueados").textContent = dados.dominiosBloqueados.length;
    document.getElementById("numCookies").textContent = dados.cookies.total;

    // Rastreadores
    renderizarRastreadores(dados);

    // Bloqueados
    renderizarBloqueados(dados.dominiosBloqueados);

    // Cookies detalhados
    renderizarCookies(dados.cookies, dados.sincronismoCookies);

    // Armazenamento
    renderizarArmazenamento(dados.armazenamentoLocal);

    // Canvas / Impressão digital
    renderizarCanvas(dados.impressaoDigital);

    // Sequestro / Hijacking
    renderizarSequestro(dados.sequestro);

    // Distribuição por categoria e todos os terceiros (Conceito A)
    renderizarDistribuicao(dados);
    renderizarTodosTerceiros(dados);

    // Relatório (Conceito B)
    renderizarRelatorio(dados);
  }

  // ==========================================
  // Nota de privacidade (barra horizontal)
  // ==========================================
  function renderizarNota(nota) {
    const elValor = document.getElementById("notaValor");
    const elBarra = document.getElementById("notaBarra");
    const elDesc = document.getElementById("notaDescricao");

    elValor.textContent = nota;
    elBarra.style.width = nota + "%";

    let cor, descricao;
    if (nota >= 80) {
      cor = "#3fb950";
      descricao = "✓ Boa privacidade. Poucos riscos detectados nesta página.";
    } else if (nota >= 60) {
      cor = "#d29922";
      descricao = "◆ Privacidade moderada. Rastreadores e cookies de terceiros presentes.";
    } else if (nota >= 40) {
      cor = "#db6d28";
      descricao = "▲ Privacidade comprometida. Múltiplas técnicas de rastreamento ativas.";
    } else {
      cor = "#f85149";
      descricao = "● Privacidade crítica! Rastreamento agressivo detectado.";
    }

    elValor.style.color = cor;
    elDesc.textContent = descricao;
  }

  // ==========================================
  // Rastreadores
  // ==========================================
  function renderizarRastreadores(dados) {
    const elPrimarios = document.getElementById("listaPrimarios");
    const elExternos = document.getElementById("listaExternos");

    if (dados.rastreadoresPrimarios.length > 0) {
      elPrimarios.innerHTML = "";
      dados.rastreadoresPrimarios.forEach((dom) => {
        elPrimarios.appendChild(criarItemDominio(dom));
      });
    }

    if (dados.rastreadoresExternos.length > 0) {
      elExternos.innerHTML = "";
      dados.rastreadoresExternos.forEach((dom) => {
        elExternos.appendChild(criarItemDominio(dom));
      });
    }
  }

  /**
   * Cria um elemento visual para um domínio com sua tag de categoria.
   */
  function criarItemDominio(dominio) {
    const item = document.createElement("div");
    item.className = "item-dominio";

    const nome = document.createElement("span");
    nome.className = "dominio-nome";
    nome.textContent = dominio;

    const tag = document.createElement("span");
    const cat = identificarCategoria(dominio);
    tag.className = "dominio-tag tag-" + cat.classe;
    tag.textContent = cat.rotulo;

    item.appendChild(nome);
    item.appendChild(tag);
    return item;
  }

  /**
   * Identifica a categoria de um domínio por heurística simples.
   */
  function identificarCategoria(dominio) {
    const categorias = {
      propaganda: { rotulo: "Propaganda", classe: "propaganda" },
      metricas: { rotulo: "Métricas", classe: "metricas" },
      social: { rotulo: "Social", classe: "social" },
      impressao_digital: { rotulo: "Fingerprint", classe: "impressao_digital" },
      cdn: { rotulo: "CDN", classe: "cdn" },
      desconhecido: { rotulo: "Outro", classe: "desconhecido" }
    };

    // Heurísticas de classificação por nome de domínio
    if (/ad[sx]?[.\-]|double|syndic|criteo|taboola|outbrain|pubmatic|bidswitch|openx/i.test(dominio)) {
      return categorias.propaganda;
    }
    if (/analytics|mixpanel|hotjar|segment|heap|chart|newrelic|statcounter|scorecardresearch|comscore/i.test(dominio)) {
      return categorias.metricas;
    }
    if (/facebook|twitter|linkedin|pinterest|tiktok|instagram|reddit|fbcdn/i.test(dominio)) {
      return categorias.social;
    }
    if (/fingerprint|iovation|threatmetrix|maxmind|bluecava/i.test(dominio)) {
      return categorias.impressao_digital;
    }
    if (/cdn\./i.test(dominio)) {
      return categorias.cdn;
    }
    return categorias.desconhecido;
  }

  // ==========================================
  // Bloqueados
  // ==========================================
  function renderizarBloqueados(bloqueados) {
    const el = document.getElementById("listaBloqueados");
    if (bloqueados.length > 0) {
      el.innerHTML = "";
      bloqueados.forEach((dom) => {
        el.appendChild(criarItemDominio(dom));
      });
    }
  }

  // ==========================================
  // Cookies detalhados
  // ==========================================
  function renderizarCookies(cookies, sincronismo) {
    document.getElementById("cookiePrimSessao").textContent = cookies.primario.sessao;
    document.getElementById("cookiePrimPerm").textContent = cookies.primario.permanente;
    document.getElementById("cookieTercSessao").textContent = cookies.terceiro.sessao;
    document.getElementById("cookieTercPerm").textContent = cookies.terceiro.permanente;
    document.getElementById("cookieLongaDuracao").textContent = cookies.longa_duracao;

    // Sincronismo de cookies
    if (sincronismo && sincronismo.encontrado) {
      const secao = document.getElementById("secaoSincronismo");
      secao.style.display = "block";
      const lista = document.getElementById("listaSincronismo");
      lista.innerHTML = "";

      sincronismo.pares.forEach((par) => {
        const item = document.createElement("div");
        item.className = "item-dominio";
        item.innerHTML =
          '<span class="dominio-nome">' + escaparHtml(par.origem) + " → " + escaparHtml(par.destino) + '</span>' +
          '<span class="dominio-tag tag-propaganda">Sync</span>';
        lista.appendChild(item);
      });
    }
  }

  // ==========================================
  // Armazenamento HTML5
  // ==========================================
  function renderizarArmazenamento(armaz) {
    const elStatus = document.getElementById("statusArmazenamento");
    const elDetalhe = document.getElementById("detalheArmazenamento");

    if (armaz.encontrado) {
      elStatus.className = "indicador indicador-alerta";
      elStatus.textContent = "◆ Armazenamento detectado";
      elDetalhe.style.display = "block";

      document.getElementById("qtdChaves").textContent = armaz.chaves.length;
      document.getElementById("tamArmazenamento").textContent = formatarTamanho(armaz.tamanhoBytes);

      const elLista = document.getElementById("listaChaves");
      elLista.innerHTML = "";

      armaz.chaves.slice(0, 15).forEach((entrada) => {
        const item = document.createElement("div");
        item.className = "item-chave";

        const tipoLabel = entrada.tipo === "local" ? "local" :
                          entrada.tipo === "sessao" ? "sessão" : "indexeddb";

        item.innerHTML =
          '<span class="chave-nome">' + escaparHtml(entrada.nome) + '</span>' +
          '<span class="chave-tipo">' + tipoLabel + '</span>' +
          (entrada.previa ? '<span class="chave-previa">' + escaparHtml(entrada.previa) + '</span>' : '');
        elLista.appendChild(item);
      });

      if (armaz.chaves.length > 15) {
        const mais = document.createElement("div");
        mais.className = "vazio";
        mais.textContent = "+ " + (armaz.chaves.length - 15) + " chaves adicionais...";
        elLista.appendChild(mais);
      }
    }
  }

  // ==========================================
  // Canvas / Impressão digital
  // ==========================================
  function renderizarCanvas(impressao) {
    const elStatus = document.getElementById("statusCanvas");
    const elDetalhe = document.getElementById("detalheCanvas");

    if (impressao.encontrado) {
      elStatus.className = "indicador indicador-perigo";
      elStatus.textContent = "● Fingerprinting detectado!";
      elDetalhe.style.display = "block";
      document.getElementById("qtdCanvas").textContent = impressao.ocorrencias;
    }
  }

  // ==========================================
  // Sequestro / Hijacking
  // ==========================================
  function renderizarSequestro(sequestro) {
    const elStatus = document.getElementById("statusSequestro");
    const elLista = document.getElementById("listaSequestro");

    if (sequestro.encontrado && sequestro.alertas.length > 0) {
      elStatus.className = "indicador indicador-perigo";
      elStatus.textContent = "● " + sequestro.alertas.length + " ameaça(s) detectada(s)";
      elLista.style.display = "block";
      elLista.innerHTML = "";

      sequestro.alertas.forEach((alerta) => {
        const item = document.createElement("div");
        item.className = "item-ameaca";

        const labelCat = traduzirCategoriaAmeaca(alerta.categoria);
        item.innerHTML =
          '<span class="ameaca-categoria">' + labelCat + '</span>' +
          '<span class="ameaca-descricao">' + escaparHtml(alerta.descricao) + '</span>';
        elLista.appendChild(item);
      });
    }
  }

  function traduzirCategoriaAmeaca(cat) {
    const mapa = {
      redirecionamento_rastreador: "↪ Redirecionamento Suspeito",
      script_perigoso: "▲ Script Perigoso",
      ip_direto: "◆ Requisição Direta a IP",
      dados_codificados: "● Dados Codificados na URL",
      iframe_oculto: "◉ iFrame Oculto",
      framework_ataque: "⚡ Framework de Ataque!",
      script_inline_suspeito: "▲ Script Inline Suspeito"
    };
    return mapa[cat] || cat;
  }

  // ==========================================
  // Navegação por abas
  // ==========================================
  function configurarAbas() {
    document.querySelectorAll(".aba").forEach((btn) => {
      btn.addEventListener("click", () => {
        // Desativar todas as abas
        document.querySelectorAll(".aba").forEach(b => b.classList.remove("ativa"));
        document.querySelectorAll(".conteudo-aba").forEach(c => c.classList.remove("ativo"));

        // Ativar a aba clicada
        btn.classList.add("ativa");
        const alvo = document.getElementById(btn.dataset.alvo);
        if (alvo) alvo.classList.add("ativo");
      });
    });
  }

  // ==========================================
  // Toggle de bloqueio
  // ==========================================
  function configurarBloqueio() {
    const chk = document.getElementById("chkBloqueio");
    const rotulo = document.getElementById("rotuloBloqueio");

    // Carregar estado atual
    browser.runtime.sendMessage({ tipo: "obterPreferencias" }).then((resp) => {
      if (resp && resp.ok) {
        chk.checked = resp.preferencias.bloqueioAtivo;
        rotulo.textContent = chk.checked ? "Proteção ativa" : "Proteção inativa";
      }
    });

    chk.addEventListener("change", () => {
      browser.runtime.sendMessage({
        tipo: "alternarBloqueio",
        ativo: chk.checked
      });
      rotulo.textContent = chk.checked ? "Proteção ativa" : "Proteção inativa";
    });
  }

  // ==========================================
  // Botões
  // ==========================================
  function configurarBotoes() {
    document.getElementById("btnAjustes").addEventListener("click", () => {
      browser.runtime.openOptionsPage();
    });

    // Botão atualizar — recarrega os dados do monitor
    document.getElementById("btnAtualizar").addEventListener("click", () => {
      carregarDados();
    });

    // Botão exportar relatório como texto para clipboard
    document.getElementById("btnExportar").addEventListener("click", () => {
      if (!_dadosAtuais) return;
      const texto = gerarTextoRelatorio(_dadosAtuais);
      navigator.clipboard.writeText(texto).then(() => {
        const status = document.getElementById("statusExportar");
        status.textContent = "✓ Relatório copiado!";
        setTimeout(() => { status.textContent = ""; }, 3000);
      }).catch(() => {
        // Fallback: selecionar texto em textarea temporário
        const area = document.createElement("textarea");
        area.value = texto;
        document.body.appendChild(area);
        area.select();
        document.execCommand("copy");
        document.body.removeChild(area);
        const status = document.getElementById("statusExportar");
        status.textContent = "✓ Relatório copiado!";
        setTimeout(() => { status.textContent = ""; }, 3000);
      });
    });
  }

  // ==========================================
  // Utilitários
  // ==========================================
  function formatarTamanho(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  function escaparHtml(texto) {
    const div = document.createElement("div");
    div.textContent = texto;
    return div.innerHTML;
  }

  // ==========================================
  // Distribuição por categoria — Conceito A
  // ==========================================

  /**
   * Agrupa rastreadores por categoria e renderiza barras proporcionais.
   */
  function renderizarDistribuicao(dados) {
    const el = document.getElementById("distribuicaoCategorias");
    const todos = [
      ...dados.rastreadoresPrimarios,
      ...dados.rastreadoresExternos
    ];

    if (todos.length === 0) return;

    // Contar por categoria
    const contagem = {};
    todos.forEach(dom => {
      const cat = identificarCategoria(dom);
      contagem[cat.classe] = (contagem[cat.classe] || 0) + 1;
    });

    const maximo = Math.max(...Object.values(contagem));
    el.innerHTML = "";

    const ordemCategorias = [
      { classe: "propaganda", nome: "Propaganda" },
      { classe: "metricas", nome: "Métricas" },
      { classe: "social", nome: "Social" },
      { classe: "impressao_digital", nome: "Fingerprint" },
      { classe: "cdn", nome: "CDN" },
      { classe: "desconhecido", nome: "Outro" }
    ];

    ordemCategorias.forEach(cat => {
      const qtd = contagem[cat.classe] || 0;
      if (qtd === 0) return;

      const pct = Math.round((qtd / maximo) * 100);

      const item = document.createElement("div");
      item.className = "dist-item";
      item.innerHTML =
        '<span class="dist-nome">' + cat.nome + '</span>' +
        '<div class="dist-barra-fundo">' +
          '<div class="dist-barra-preenchimento dist-' + cat.classe + '" style="width:' + pct + '%"></div>' +
        '</div>' +
        '<span class="dist-num">' + qtd + '</span>';
      el.appendChild(item);
    });
  }

  // ==========================================
  // Todos os domínios de terceiros — Conceito A
  // ==========================================

  /**
   * Lista TODOS os domínios de terceiros, indicando quais são rastreadores.
   */
  function renderizarTodosTerceiros(dados) {
    const el = document.getElementById("listaTodosTerceiros");

    if (dados.dominiosTerceiros.length === 0) return;

    el.innerHTML = "";
    const rastreadoresSet = new Set(dados.rastreadoresEncontrados);

    dados.dominiosTerceiros.forEach(dom => {
      const item = document.createElement("div");
      item.className = "item-dominio";

      const nome = document.createElement("span");
      nome.className = "dominio-nome";
      nome.textContent = dom;

      const tag = document.createElement("span");
      if (rastreadoresSet.has(dom)) {
        const cat = identificarCategoria(dom);
        tag.className = "dominio-tag tag-" + cat.classe;
        tag.textContent = cat.rotulo;
      } else {
        tag.className = "dominio-tag tag-desconhecido";
        tag.textContent = "Terceiro";
      }

      item.appendChild(nome);
      item.appendChild(tag);
      el.appendChild(item);
    });
  }

  // ==========================================
  // Relatório — Conceito B
  // ==========================================

  /**
   * Preenche a aba Relatório com dados estatísticos.
   */
  function renderizarRelatorio(dados) {
    // Resumo
    document.getElementById("relSite").textContent = dados.hostPrincipal || dados.endereco || "—";

    const momentoCriacao = dados.momentoCriacao;
    if (momentoCriacao) {
      const data = new Date(momentoCriacao);
      document.getElementById("relHorario").textContent =
        data.toLocaleDateString("pt-BR") + " " + data.toLocaleTimeString("pt-BR");
    }

    document.getElementById("relRequisicoes").textContent = dados.requisicoes;
    document.getElementById("relBloqueios").textContent = dados.bloqueios;

    const taxa = dados.requisicoes > 0
      ? Math.round((dados.bloqueios / dados.requisicoes) * 100)
      : 0;
    document.getElementById("relTaxaBloqueio").textContent = taxa + "%";

    const elNota = document.getElementById("relNota");
    elNota.textContent = dados.notaPrivacidade + "/100";
    if (dados.notaPrivacidade >= 80) elNota.style.color = "#3fb950";
    else if (dados.notaPrivacidade >= 60) elNota.style.color = "#d29922";
    else if (dados.notaPrivacidade >= 40) elNota.style.color = "#db6d28";
    else elNota.style.color = "#f85149";

    // Categorias
    document.getElementById("relCatTerceiros").textContent = dados.dominiosTerceiros.length;
    document.getElementById("relCatExtRast").textContent = dados.rastreadoresExternos.length;
    document.getElementById("relCatPrimRast").textContent = dados.rastreadoresPrimarios.length;
    document.getElementById("relCatBloq").textContent = dados.dominiosBloqueados.length;
    document.getElementById("relCatCookies").textContent = dados.cookies.total;
    document.getElementById("relCatLonga").textContent = dados.cookies.longa_duracao;

    // Detecções
    function setDetStatus(elId, detectado, label) {
      const el = document.getElementById(elId);
      if (detectado) {
        el.textContent = label || "Detectado";
        el.className = "relatorio-det-status det-detectado";
      } else {
        el.textContent = "Seguro";
        el.className = "relatorio-det-status det-seguro";
      }
    }

    setDetStatus("relDetStorage", dados.armazenamentoLocal.encontrado,
      dados.armazenamentoLocal.encontrado ? dados.armazenamentoLocal.chaves.length + " chaves" : null);
    setDetStatus("relDetCanvas", dados.impressaoDigital.encontrado,
      dados.impressaoDigital.encontrado ? dados.impressaoDigital.ocorrencias + " ocorrência(s)" : null);
    setDetStatus("relDetSync", dados.sincronismoCookies.encontrado,
      dados.sincronismoCookies.encontrado ? dados.sincronismoCookies.pares.length + " par(es)" : null);
    setDetStatus("relDetHijack", dados.sequestro.encontrado,
      dados.sequestro.encontrado ? dados.sequestro.alertas.length + " alerta(s)" : null);
  }

  /**
   * Gera uma versão em texto plano do relatório para exportação.
   */
  function gerarTextoRelatorio(dados) {
    const linhas = [];
    linhas.push("═══════════════════════════════════════");
    linhas.push("  THIRDEYE — RELATÓRIO DE PRIVACIDADE");
    linhas.push("═══════════════════════════════════════");
    linhas.push("");
    linhas.push("Página: " + (dados.hostPrincipal || dados.endereco));
    linhas.push("Data: " + new Date(dados.momentoCriacao).toLocaleString("pt-BR"));
    linhas.push("Nota de Privacidade: " + dados.notaPrivacidade + "/100");
    linhas.push("");

    linhas.push("── ESTATÍSTICAS ──");
    linhas.push("Requisições totais: " + dados.requisicoes);
    linhas.push("Requisições bloqueadas: " + dados.bloqueios);
    const taxa = dados.requisicoes > 0 ? Math.round((dados.bloqueios / dados.requisicoes) * 100) : 0;
    linhas.push("Taxa de bloqueio: " + taxa + "%");
    linhas.push("");

    linhas.push("── RASTREADORES ──");
    linhas.push("Domínios de terceiros: " + dados.dominiosTerceiros.length);
    linhas.push("Rastreadores externos: " + dados.rastreadoresExternos.length);
    linhas.push("Rastreadores primários: " + dados.rastreadoresPrimarios.length);
    linhas.push("Domínios bloqueados: " + dados.dominiosBloqueados.length);
    if (dados.dominiosBloqueados.length > 0) {
      dados.dominiosBloqueados.forEach(d => linhas.push("  ✕ " + d));
    }
    linhas.push("");

    linhas.push("── COOKIES ──");
    linhas.push("Total: " + dados.cookies.total);
    linhas.push("1ª parte (sessão): " + dados.cookies.primario.sessao);
    linhas.push("1ª parte (permanente): " + dados.cookies.primario.permanente);
    linhas.push("3ª parte (sessão): " + dados.cookies.terceiro.sessao);
    linhas.push("3ª parte (permanente): " + dados.cookies.terceiro.permanente);
    linhas.push("Longa duração: " + dados.cookies.longa_duracao);
    linhas.push("");

    linhas.push("── DETECÇÕES ──");
    linhas.push("Armazenamento HTML5: " + (dados.armazenamentoLocal.encontrado ? "DETECTADO (" + dados.armazenamentoLocal.chaves.length + " chaves)" : "Seguro"));
    linhas.push("Canvas Fingerprint: " + (dados.impressaoDigital.encontrado ? "DETECTADO (" + dados.impressaoDigital.ocorrencias + " ocorrências)" : "Seguro"));
    linhas.push("Sincronismo de cookies: " + (dados.sincronismoCookies.encontrado ? "DETECTADO" : "Seguro"));
    linhas.push("Ameaças de sequestro: " + (dados.sequestro.encontrado ? "DETECTADO (" + dados.sequestro.alertas.length + " alertas)" : "Seguro"));
    linhas.push("");
    linhas.push("═══════════════════════════════════════");
    linhas.push("Gerado por ThirdEye v1.0.0");

    return linhas.join("\n");
  }
});
