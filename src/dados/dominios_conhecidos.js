/**
 * ThirdEye — Base de Domínios Rastreadores Conhecidos
 *
 * Estrutura: array de objetos { dominio, tipo }
 * Tipos: "propaganda", "metricas", "social", "impressao_digital", "cdn"
 *
 * Fontes de referência: EasyList, EasyPrivacy, listas públicas.
 * Esta lista é uma amostra representativa — não é exaustiva.
 */

const LISTA_RASTREADORES = [
  // --- Propaganda e publicidade ---
  { dominio: "doubleclick.net", tipo: "propaganda" },
  { dominio: "googlesyndication.com", tipo: "propaganda" },
  { dominio: "googleadservices.com", tipo: "propaganda" },
  { dominio: "googletagservices.com", tipo: "propaganda" },
  { dominio: "adnxs.com", tipo: "propaganda" },
  { dominio: "adsrvr.org", tipo: "propaganda" },
  { dominio: "adform.net", tipo: "propaganda" },
  { dominio: "advertising.com", tipo: "propaganda" },
  { dominio: "criteo.com", tipo: "propaganda" },
  { dominio: "criteo.net", tipo: "propaganda" },
  { dominio: "casalemedia.com", tipo: "propaganda" },
  { dominio: "media.net", tipo: "propaganda" },
  { dominio: "outbrain.com", tipo: "propaganda" },
  { dominio: "taboola.com", tipo: "propaganda" },
  { dominio: "revcontent.com", tipo: "propaganda" },
  { dominio: "mgid.com", tipo: "propaganda" },
  { dominio: "bidswitch.net", tipo: "propaganda" },
  { dominio: "openx.net", tipo: "propaganda" },
  { dominio: "pubmatic.com", tipo: "propaganda" },
  { dominio: "rubiconproject.com", tipo: "propaganda" },
  { dominio: "smartadserver.com", tipo: "propaganda" },
  { dominio: "contextweb.com", tipo: "propaganda" },
  { dominio: "indexexchange.com", tipo: "propaganda" },
  { dominio: "moatads.com", tipo: "propaganda" },
  { dominio: "serving-sys.com", tipo: "propaganda" },
  { dominio: "sharethrough.com", tipo: "propaganda" },
  { dominio: "yieldmo.com", tipo: "propaganda" },
  { dominio: "admob.com", tipo: "propaganda" },
  { dominio: "adcolony.com", tipo: "propaganda" },

  // --- Métricas e analytics ---
  { dominio: "google-analytics.com", tipo: "metricas" },
  { dominio: "analytics.google.com", tipo: "metricas" },
  { dominio: "googletagmanager.com", tipo: "metricas" },
  { dominio: "hotjar.com", tipo: "metricas" },
  { dominio: "mixpanel.com", tipo: "metricas" },
  { dominio: "amplitude.com", tipo: "metricas" },
  { dominio: "segment.io", tipo: "metricas" },
  { dominio: "segment.com", tipo: "metricas" },
  { dominio: "heapanalytics.com", tipo: "metricas" },
  { dominio: "fullstory.com", tipo: "metricas" },
  { dominio: "mouseflow.com", tipo: "metricas" },
  { dominio: "crazyegg.com", tipo: "metricas" },
  { dominio: "luckyorange.com", tipo: "metricas" },
  { dominio: "chartbeat.com", tipo: "metricas" },
  { dominio: "chartbeat.net", tipo: "metricas" },
  { dominio: "newrelic.com", tipo: "metricas" },
  { dominio: "nr-data.net", tipo: "metricas" },
  { dominio: "omtrdc.net", tipo: "metricas" },
  { dominio: "demdex.net", tipo: "metricas" },
  { dominio: "kissmetrics.com", tipo: "metricas" },
  { dominio: "woopra.com", tipo: "metricas" },
  { dominio: "matomo.cloud", tipo: "metricas" },
  { dominio: "statcounter.com", tipo: "metricas" },
  { dominio: "clicky.com", tipo: "metricas" },
  { dominio: "quantserve.com", tipo: "metricas" },
  { dominio: "scorecardresearch.com", tipo: "metricas" },
  { dominio: "comscore.com", tipo: "metricas" },

  // --- Redes sociais ---
  { dominio: "facebook.net", tipo: "social" },
  { dominio: "facebook.com", tipo: "social" },
  { dominio: "fbcdn.net", tipo: "social" },
  { dominio: "connect.facebook.net", tipo: "social" },
  { dominio: "twitter.com", tipo: "social" },
  { dominio: "platform.twitter.com", tipo: "social" },
  { dominio: "t.co", tipo: "social" },
  { dominio: "linkedin.com", tipo: "social" },
  { dominio: "platform.linkedin.com", tipo: "social" },
  { dominio: "snap.licdn.com", tipo: "social" },
  { dominio: "pinterest.com", tipo: "social" },
  { dominio: "tiktok.com", tipo: "social" },
  { dominio: "analytics.tiktok.com", tipo: "social" },
  { dominio: "instagram.com", tipo: "social" },
  { dominio: "reddit.com", tipo: "social" },
  { dominio: "redditstatic.com", tipo: "social" },

  // --- Impressão digital (fingerprinting) ---
  { dominio: "fingerprintjs.com", tipo: "impressao_digital" },
  { dominio: "iovation.com", tipo: "impressao_digital" },
  { dominio: "threatmetrix.com", tipo: "impressao_digital" },
  { dominio: "maxmind.com", tipo: "impressao_digital" },
  { dominio: "bluecava.com", tipo: "impressao_digital" },
  { dominio: "deviceinfo.me", tipo: "impressao_digital" },
  { dominio: "browserleaks.com", tipo: "impressao_digital" },

  // --- CDNs com rastreamento ---
  { dominio: "cloudflare-insights.com", tipo: "cdn" },
  { dominio: "cdn.mxpnl.com", tipo: "cdn" },
  { dominio: "cdn.heapanalytics.com", tipo: "cdn" },
  { dominio: "cdn.segment.com", tipo: "cdn" }
];

// ==========================================
// Índice rápido para consulta
// ==========================================

// Set com todos os domínios para busca O(1)
const _indiceDominios = new Set();
// Mapa domínio → tipo para categorização
const _mapaTipos = {};

for (const entrada of LISTA_RASTREADORES) {
  _indiceDominios.add(entrada.dominio);
  _mapaTipos[entrada.dominio] = entrada.tipo;
}

/**
 * Verifica se um hostname é um domínio rastreador conhecido.
 * Faz matching por sufixo (ex: "ads.doubleclick.net" → true).
 */
function verificarRastreador(hostname) {
  if (!hostname) return false;
  if (_indiceDominios.has(hostname)) return true;
  // Verificar se é um subdomínio de algum rastreador
  for (const conhecido of _indiceDominios) {
    if (hostname.endsWith("." + conhecido)) return true;
  }
  return false;
}

/**
 * Retorna o tipo/categoria de um domínio rastreador.
 * Ex: "doubleclick.net" → "propaganda"
 */
function obterTipoRastreador(hostname) {
  if (_mapaTipos[hostname]) return _mapaTipos[hostname];
  for (const conhecido of _indiceDominios) {
    if (hostname.endsWith("." + conhecido)) {
      return _mapaTipos[conhecido];
    }
  }
  return "desconhecido";
}
