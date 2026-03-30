/**
 * ThirdEye — Lógica da Página de Ajustes
 *
 * Gerencia preferências, listas de bloqueio e permissão,
 * importação/exportação de listas, e sensibilidade do score.
 */

document.addEventListener("DOMContentLoaded", () => {
  let configAtual = {
    bloqueioAtivo: true,
    listaPersonalizada: [],
    listaPermitidos: [],
    sensibilidade: 1  // 0=relaxado, 1=equilibrado, 2=rigoroso
  };

  carregarConfig();

  // ==========================================
  // Carregar configurações
  // ==========================================
  function carregarConfig() {
    browser.runtime.sendMessage({ tipo: "obterPreferencias" }).then((resp) => {
      if (resp && resp.ok) {
        configAtual = { ...configAtual, ...resp.preferencias };
        exibirConfig();
      }
    });
  }

  function exibirConfig() {
    document.getElementById("chkBloqueio").checked = configAtual.bloqueioAtivo;
    exibirLista("containerBloqueio", configAtual.listaPersonalizada, "bloqueio");
    exibirLista("containerPermissao", configAtual.listaPermitidos, "permissao");

    // Sensibilidade
    const slider = document.getElementById("sliderSensibilidade");
    slider.value = configAtual.sensibilidade || 1;
    atualizarDescSensibilidade(parseInt(slider.value));
  }

  // ==========================================
  // Renderizar listas
  // ==========================================
  function exibirLista(containerId, itens, tipoLista) {
    const container = document.getElementById(containerId);

    if (itens.length === 0) {
      container.innerHTML = '<div class="estado-vazio">' +
        (tipoLista === "bloqueio"
          ? "Nenhum domínio personalizado adicionado."
          : "Nenhum domínio na lista de permissão.") +
        '</div>';
      return;
    }

    container.innerHTML = "";
    itens.forEach((dominio, idx) => {
      const item = document.createElement("div");
      item.className = "item-lista";
      item.innerHTML =
        '<span>' + dominio + '</span>' +
        '<button class="btn btn-perigo btn-pequeno" data-lista="' + tipoLista + '" data-idx="' + idx + '">✕ Remover</button>';
      container.appendChild(item);
    });

    // Eventos de remoção
    container.querySelectorAll("button").forEach((btn) => {
      btn.addEventListener("click", () => {
        const lista = btn.dataset.lista;
        const idx = parseInt(btn.dataset.idx);
        if (lista === "bloqueio") {
          configAtual.listaPersonalizada.splice(idx, 1);
        } else {
          configAtual.listaPermitidos.splice(idx, 1);
        }
        exibirConfig();
      });
    });
  }

  // ==========================================
  // Adicionar domínio
  // ==========================================
  function adicionarDominio(inputId, chaveConfig) {
    const input = document.getElementById(inputId);
    let dominio = input.value.trim().toLowerCase();

    if (!dominio) return;

    // Limpar protocolo
    dominio = dominio.replace(/^https?:\/\//, "").replace(/\/.*$/, "");

    // Validar formato
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(dominio)) {
      input.style.borderColor = "#f85149";
      setTimeout(() => { input.style.borderColor = "#21262d"; }, 2000);
      return;
    }

    // Verificar duplicata
    if (configAtual[chaveConfig].includes(dominio)) {
      input.style.borderColor = "#d29922";
      setTimeout(() => { input.style.borderColor = "#21262d"; }, 2000);
      return;
    }

    configAtual[chaveConfig].push(dominio);
    input.value = "";
    exibirConfig();
  }

  document.getElementById("btnAdicionarBloqueio").addEventListener("click", () => {
    adicionarDominio("inputBloqueio", "listaPersonalizada");
  });

  document.getElementById("btnAdicionarPermissao").addEventListener("click", () => {
    adicionarDominio("inputPermissao", "listaPermitidos");
  });

  // Enter para adicionar
  document.getElementById("inputBloqueio").addEventListener("keydown", (e) => {
    if (e.key === "Enter") adicionarDominio("inputBloqueio", "listaPersonalizada");
  });

  document.getElementById("inputPermissao").addEventListener("keydown", (e) => {
    if (e.key === "Enter") adicionarDominio("inputPermissao", "listaPermitidos");
  });

  // ==========================================
  // Importar / Exportar listas — Conceito A
  // ==========================================

  /**
   * Exporta uma lista como arquivo .txt (um domínio por linha).
   */
  function exportarLista(itens, nomeArquivo) {
    if (itens.length === 0) return;
    const conteudo = itens.join("\n");
    const blob = new Blob([conteudo], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = nomeArquivo;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  /**
   * Importa domínios de um arquivo .txt (um por linha).
   * Aceita .txt, .csv, .json — lê como texto e parseia linhas.
   */
  function importarLista(arquivo, chaveConfig) {
    const leitor = new FileReader();
    leitor.onload = function (evento) {
      const texto = evento.target.result;
      let dominios = [];

      // Tentar JSON primeiro
      try {
        const json = JSON.parse(texto);
        if (Array.isArray(json)) {
          dominios = json.filter(d => typeof d === "string");
        }
      } catch (e) {
        // Não é JSON — tratar como texto (um domínio por linha)
        dominios = texto.split(/[\n\r,;]+/).map(d => d.trim().toLowerCase()).filter(Boolean);
      }

      // Filtrar formatos válidos e remover duplicatas
      const validos = dominios.filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d));
      const novos = validos.filter(d => !configAtual[chaveConfig].includes(d));

      if (novos.length > 0) {
        configAtual[chaveConfig] = configAtual[chaveConfig].concat(novos);
        exibirConfig();
      }
    };
    leitor.readAsText(arquivo);
  }

  // Exportar bloqueio
  document.getElementById("btnExportarBloqueio").addEventListener("click", () => {
    exportarLista(configAtual.listaPersonalizada, "thirdeye_bloqueio.txt");
  });

  // Importar bloqueio
  document.getElementById("btnImportarBloqueio").addEventListener("click", () => {
    document.getElementById("arquivoBloqueio").click();
  });
  document.getElementById("arquivoBloqueio").addEventListener("change", (e) => {
    if (e.target.files[0]) {
      importarLista(e.target.files[0], "listaPersonalizada");
      e.target.value = ""; // reset para permitir re-importação
    }
  });

  // Exportar permissão
  document.getElementById("btnExportarPermissao").addEventListener("click", () => {
    exportarLista(configAtual.listaPermitidos, "thirdeye_permissao.txt");
  });

  // Importar permissão
  document.getElementById("btnImportarPermissao").addEventListener("click", () => {
    document.getElementById("arquivoPermissao").click();
  });
  document.getElementById("arquivoPermissao").addEventListener("change", (e) => {
    if (e.target.files[0]) {
      importarLista(e.target.files[0], "listaPermitidos");
      e.target.value = "";
    }
  });

  // ==========================================
  // Sensibilidade do score — Conceito A
  // ==========================================
  const descricoesSensibilidade = [
    "Modo relaxado — penalidades reduzidas. Ideal para usuários que priorizam funcionalidade.",
    "Modo equilibrado — pesos padrão para cada categoria.",
    "Modo rigoroso — penalidades ampliadas. Ideal para usuários que priorizam privacidade máxima."
  ];

  function atualizarDescSensibilidade(valor) {
    document.getElementById("descSensibilidade").textContent = descricoesSensibilidade[valor] || descricoesSensibilidade[1];
  }

  document.getElementById("sliderSensibilidade").addEventListener("input", (e) => {
    const valor = parseInt(e.target.value);
    atualizarDescSensibilidade(valor);
    configAtual.sensibilidade = valor;
  });

  // ==========================================
  // Salvar configurações
  // ==========================================
  document.getElementById("btnSalvar").addEventListener("click", () => {
    configAtual.bloqueioAtivo = document.getElementById("chkBloqueio").checked;
    configAtual.sensibilidade = parseInt(document.getElementById("sliderSensibilidade").value);

    browser.runtime.sendMessage({
      tipo: "salvarPreferencias",
      preferencias: configAtual
    }).then((resp) => {
      if (resp && resp.ok) {
        const status = document.getElementById("statusSalvar");
        status.textContent = "✓ Configurações salvas!";
        setTimeout(() => { status.textContent = ""; }, 3000);
      }
    });
  });
});
