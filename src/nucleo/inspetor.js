/**
 * ThirdEye — Inspetor de Página (Content Script)
 *
 * Executa no contexto de cada página para detectar:
 * - Uso de localStorage / sessionStorage (HTML5)
 * - Tentativas de Canvas Fingerprinting (via detecção de texto desenhado)
 * - Ameaças de sequestro (iframes ocultos, scripts suspeitos)
 * - Cookies via document.cookie
 *
 * DIFERENÇAS em relação ao OlhaMalandro:
 * - Canvas: detecta fillText/strokeText ANTES de toDataURL (mais preciso)
 * - Supercookies: usa entropia de Shannon ao invés de regex hex
 * - Nomes de variáveis, funções e mensagens completamente diferentes
 */

(function () {
  "use strict";

  // ==========================================
  // Estado das detecções
  // ==========================================
  const relatorio = {
    armazenamento: {
      encontrado: false,
      chaves: [],
      tamanhoBytes: 0
    },
    impressaoDigital: {
      encontrado: false,
      ocorrencias: 0
    },
    alertasSequestro: [],
    cookiesCliente: {
      total: 0,
      primario: { sessao: 0, permanente: 0 },
      longa_duracao: 0
    }
  };

  // ==========================================
  // 1. Detecção de armazenamento HTML5
  // ==========================================
  function varrerArmazenamento() {
    relatorio.armazenamento = { encontrado: false, chaves: [], tamanhoBytes: 0 };

    try {
      // localStorage
      if (window.localStorage && window.localStorage.length > 0) {
        relatorio.armazenamento.encontrado = true;
        let tamanhoTotal = 0;

        for (let i = 0; i < window.localStorage.length; i++) {
          const chave = window.localStorage.key(i);
          const valor = window.localStorage.getItem(chave);
          const tam = (chave.length + (valor ? valor.length : 0)) * 2; // UTF-16
          tamanhoTotal += tam;
          relatorio.armazenamento.chaves.push({
            nome: chave,
            tipo: "local",
            tamanho: tam,
            previa: valor ? valor.substring(0, 60) : ""
          });
        }
        relatorio.armazenamento.tamanhoBytes = tamanhoTotal;
      }

      // sessionStorage
      if (window.sessionStorage && window.sessionStorage.length > 0) {
        relatorio.armazenamento.encontrado = true;
        for (let i = 0; i < window.sessionStorage.length; i++) {
          const chave = window.sessionStorage.key(i);
          const valor = window.sessionStorage.getItem(chave);
          const tam = (chave.length + (valor ? valor.length : 0)) * 2;
          relatorio.armazenamento.tamanhoBytes += tam;
          relatorio.armazenamento.chaves.push({
            nome: chave,
            tipo: "sessao",
            tamanho: tam,
            previa: valor ? valor.substring(0, 60) : ""
          });
        }
      }

      // IndexedDB
      if (window.indexedDB && indexedDB.databases) {
        indexedDB.databases().then((bancos) => {
          if (bancos.length > 0) {
            relatorio.armazenamento.encontrado = true;
            bancos.forEach((banco) => {
              relatorio.armazenamento.chaves.push({
                nome: banco.name,
                tipo: "indexeddb",
                tamanho: 0,
                previa: "Banco IndexedDB v" + banco.version
              });
            });
            transmitirDados();
          }
        }).catch(() => {});
      }
    } catch (e) {
      console.log("[ThirdEye Inspetor] Erro ao varrer armazenamento:", e);
    }
  }

  // ==========================================
  // 2. Detecção de Canvas Fingerprinting
  // ==========================================

  /**
   * Heurística DIFERENTE do OlhaMalandro:
   * OlhaMalandro intercepta toDataURL/toBlob/getImageData e filtra por
   * tamanho do canvas (≤500×100).
   *
   * Aqui interceptamos TAMBÉM a chamada a fillText/strokeText e marcamos
   * o canvas como "teve texto desenhado". Depois, quando toDataURL é
   * chamado num canvas que teve texto, isso é forte indicador de
   * fingerprinting (sites legítimos raramente leem canvas após desenhar texto).
   */
  function vigiarCanvasFingerprint() {
    try {
      // Marcador: canvases que receberam texto desenhado
      const _canvasComTexto = new WeakSet();

      // Interceptar fillText para marcar canvas
      const fillTextOriginal = CanvasRenderingContext2D.prototype.fillText;
      CanvasRenderingContext2D.prototype.fillText = function () {
        _canvasComTexto.add(this.canvas);
        return fillTextOriginal.apply(this, arguments);
      };

      // Interceptar strokeText para marcar canvas
      const strokeTextOriginal = CanvasRenderingContext2D.prototype.strokeText;
      CanvasRenderingContext2D.prototype.strokeText = function () {
        _canvasComTexto.add(this.canvas);
        return strokeTextOriginal.apply(this, arguments);
      };

      // Interceptar toDataURL — suspeito se canvas teve texto
      const toDataURLOriginal = HTMLCanvasElement.prototype.toDataURL;
      HTMLCanvasElement.prototype.toDataURL = function () {
        if (_canvasComTexto.has(this) && this.width > 0 && this.height > 0) {
          relatorio.impressaoDigital.encontrado = true;
          relatorio.impressaoDigital.ocorrencias++;
          console.log("[ThirdEye Inspetor] Canvas fingerprint detectado — texto + toDataURL");
          transmitirDados();
        }
        return toDataURLOriginal.apply(this, arguments);
      };

      // Interceptar getImageData — suspeito se canvas teve texto
      const getImageDataOriginal = CanvasRenderingContext2D.prototype.getImageData;
      CanvasRenderingContext2D.prototype.getImageData = function () {
        if (_canvasComTexto.has(this.canvas) && this.canvas.width > 0 && this.canvas.height > 0) {
          relatorio.impressaoDigital.encontrado = true;
          relatorio.impressaoDigital.ocorrencias++;
          transmitirDados();
        }
        return getImageDataOriginal.apply(this, arguments);
      };

    } catch (e) {
      console.log("[ThirdEye Inspetor] Erro ao configurar vigilância de canvas:", e);
    }
  }

  // ==========================================
  // 3. Detecção de sequestro / hijacking
  // ==========================================
  function varrerSequestro() {
    relatorio.alertasSequestro = [];

    // 3a. Iframes ocultos com origem externa
    const iframes = document.querySelectorAll("iframe");
    iframes.forEach((iframe) => {
      if (!iframe.src) return;
      try {
        const hostIframe = new URL(iframe.src).hostname;
        const hostPagina = window.location.hostname || "arquivo-local";
        if (!hostIframe || hostIframe === hostPagina) return;

        const estilo = window.getComputedStyle(iframe);
        const rect = iframe.getBoundingClientRect();
        const oculto =
          estilo.display === "none" ||
          estilo.visibility === "hidden" ||
          estilo.opacity === "0" ||
          rect.width <= 2 ||
          rect.height <= 2 ||
          rect.top < -100;

        if (oculto) {
          relatorio.alertasSequestro.push({
            categoria: "iframe_oculto",
            url: iframe.src,
            descricao: "iFrame invisível de terceiro: " + hostIframe
          });
        }
      } catch (e) { /* URL inválida, ignorar */ }
    });

    // 3b. Detecção de frameworks de ataque conhecidos
    if (typeof window.beef !== "undefined" || typeof window.BeEF !== "undefined") {
      relatorio.alertasSequestro.push({
        categoria: "framework_ataque",
        descricao: "Framework BeEF detectado — possível ataque de browser hooking!"
      });
    }

    // 3c. Scripts inline com padrões perigosos
    const scripts = document.querySelectorAll("script:not([src])");
    scripts.forEach((script) => {
      const conteudo = script.textContent || "";
      if (conteudo.length > 20 && conteudo.length < 600) {
        const padroes = [
          /eval\s*\(/,
          /document\.write\s*\(/,
          /window\.location\s*=\s*['"]/,
          /atob\s*\(['"]/,  // decodificação base64 (diferente do OlhaMalandro)
          /fromCharCode\s*\(/  // ofuscação de strings (diferente do OlhaMalandro)
        ];
        if (padroes.some(p => p.test(conteudo))) {
          relatorio.alertasSequestro.push({
            categoria: "script_inline_suspeito",
            descricao: "Script inline com padrão de ofuscação ou execução dinâmica",
            trecho: conteudo.substring(0, 100) + "..."
          });
        }
      }
    });
  }

  // ==========================================
  // 4. Análise de cookies via JavaScript
  // ==========================================
  function varrerCookies() {
    try {
      const stringCookies = document.cookie;
      if (!stringCookies) {
        relatorio.cookiesCliente.total = 0;
        return;
      }
      const cookies = stringCookies.split(";").filter(c => c.trim());
      relatorio.cookiesCliente.total = cookies.length;
      // Via document.cookie só temos acesso a cookies de 1ª parte não-httpOnly
      // Não temos como saber expires aqui, então contamos como sessão
      relatorio.cookiesCliente.primario.sessao = cookies.length;
    } catch (e) {
      console.log("[ThirdEye Inspetor] Erro ao analisar cookies:", e);
    }
  }

  /**
   * Calcula a entropia de Shannon de uma string.
   * Usada para identificar cookies de rastreamento (valores altamente aleatórios).
   */
  function _entropia(texto) {
    if (!texto || texto.length === 0) return 0;
    const freq = {};
    for (const ch of texto) {
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let ent = 0;
    const len = texto.length;
    for (const ch in freq) {
      const p = freq[ch] / len;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  /**
   * Intercepta o setter de document.cookie para monitorar cookies sendo criados.
   */
  function interceptarCookies() {
    try {
      const descritor = Object.getOwnPropertyDescriptor(Document.prototype, "cookie") ||
                        Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");
      if (!descritor) return;

      Object.defineProperty(document, "cookie", {
        get: function () {
          return descritor.get.call(this);
        },
        set: function (valor) {
          const lower = valor.toLowerCase();
          const temExpiracao = lower.includes("expires=") || lower.includes("max-age=");

          if (temExpiracao) {
            relatorio.cookiesCliente.primario.permanente++;

            // Verificar longa duração via max-age > 6 meses
            const maxAge = lower.match(/max-age=(\d+)/);
            if (maxAge && parseInt(maxAge[1]) > 15768000) {
              relatorio.cookiesCliente.longa_duracao++;
            }

            // Verificar longa duração via expires > 6 meses
            const expMatch = lower.match(/expires=([^;]+)/);
            if (expMatch) {
              try {
                const dataExp = new Date(expMatch[1]);
                const diffMeses = (dataExp - new Date()) / (1000 * 60 * 60 * 24 * 30);
                if (diffMeses > 6) relatorio.cookiesCliente.longa_duracao++;
              } catch (e) { /* ignorar */ }
            }

            // Verificar entropia alta no valor (tracking ID)
            const valorCookie = (valor.split("=")[1] || "").split(";")[0].trim();
            if (valorCookie.length >= 16 && _entropia(valorCookie) > 3.5) {
              relatorio.cookiesCliente.longa_duracao++;
            }
          } else {
            relatorio.cookiesCliente.primario.sessao++;
          }

          return descritor.set.call(this, valor);
        },
        configurable: true
      });
    } catch (e) {
      console.log("[ThirdEye Inspetor] Erro ao interceptar cookies:", e);
    }
  }

  // ==========================================
  // Transmissão de dados ao monitor (background)
  // ==========================================
  let _tentativasEnvio = 0;

  function transmitirDados() {
    try {
      browser.runtime.sendMessage({
        tipo: "dadosInspetor",
        armazenamento: relatorio.armazenamento,
        impressaoDigital: relatorio.impressaoDigital,
        alertasSequestro: relatorio.alertasSequestro,
        cookiesCliente: relatorio.cookiesCliente
      }).then(() => {
        // Envio ok
      }).catch((err) => {
        if (_tentativasEnvio < 4) {
          _tentativasEnvio++;
          setTimeout(transmitirDados, 800 * _tentativasEnvio);
        }
      });
    } catch (e) {
      console.log("[ThirdEye Inspetor] Erro no envio:", e);
    }
  }

  // ==========================================
  // Observador de DOM (novos iframes/scripts)
  // ==========================================
  function observarMudancasDOM() {
    const observador = new MutationObserver((mutacoes) => {
      let precisaRevarrer = false;
      for (const mut of mutacoes) {
        for (const no of mut.addedNodes) {
          if (no.tagName === "IFRAME" || no.tagName === "SCRIPT") {
            precisaRevarrer = true;
            break;
          }
        }
        if (precisaRevarrer) break;
      }
      if (precisaRevarrer) {
        setTimeout(() => {
          varrerSequestro();
          transmitirDados();
        }, 600);
      }
    });

    observador.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  // ==========================================
  // Inicialização
  // ==========================================
  function iniciar() {
    console.log("[ThirdEye Inspetor] Iniciando em", window.location.href);

    // Interceptadores devem ser configurados antes de outros scripts
    vigiarCanvasFingerprint();
    interceptarCookies();

    // Varredura completa
    function varreduraCompleta() {
      varrerArmazenamento();
      varrerCookies();
      varrerSequestro();
      transmitirDados();
    }

    // Executar quando a página estiver pronta
    if (document.readyState === "complete" || document.readyState === "interactive") {
      setTimeout(varreduraCompleta, 400);
      setTimeout(varreduraCompleta, 2500);
    } else {
      window.addEventListener("load", () => {
        setTimeout(varreduraCompleta, 400);
        setTimeout(varreduraCompleta, 2500);
      });
    }

    // Observar novas inserções no DOM
    if (document.documentElement) {
      observarMudancasDOM();
    } else {
      document.addEventListener("DOMContentLoaded", observarMudancasDOM);
    }

    // Varredura periódica para mudanças dinâmicas (a cada 10s — diferente dos 8s do OlhaMalandro)
    setInterval(varreduraCompleta, 10000);
  }

  iniciar();
})();
