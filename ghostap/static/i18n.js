/* Languages (F082). English is the source; Hindi and Telugu are DRAFT translations of the
   main screen (navigation, verdict, tiles, tabs, headings, footer) written for this
   project and not yet reviewed by a native speaker. Anything not listed stays English. */
(function () {
  "use strict";
  const DICT = {
    hi: {
      "nav.dashboard": "डैशबोर्ड", "nav.monitored": "निगरानी वाले नेटवर्क", "nav.sessions": "सत्र",
      "nav.system": "सिस्टम", "nav.whatif": "क्या-अगर",
      "tagline": "निष्क्रिय ईविल ट्विन डिटेक्टर",
      "verdict.connecting": "GhostAP से जुड़ रहे हैं…",
      "verdict.error": "लाइव कैप्चर शुरू नहीं हो सका",
      "verdict.waiting": "वाई-फ़ाई बीकन की प्रतीक्षा…",
      "verdict.learning": "सामान्य स्थिति सीखी जा रही है",
      "verdict.deauth": "“{ssid}” पर डीऑथेंटिकेशन हमला",
      "verdict.flood": "बीकन फ़्लड: एक साथ कई नकली नेटवर्क दिखे",
      "verdict.twin": "“{ssid}” पर ईविल ट्विन का संदेह",
      "verdict.suspicious": "“{ssid}” पर संदिग्ध एक्सेस पॉइंट",
      "verdict.clear": "सब ठीक: {nets} नेटवर्क पर {aps} एक्सेस पॉइंट सामान्य दिखते हैं",
      "tile.networks": "नेटवर्क", "tile.aps": "एक्सेस पॉइंट", "tile.high": "HIGH अलर्ट",
      "tile.medium": "MEDIUM अलर्ट", "tile.nameonly": "केवल-नाम जाँच",
      "tab.alerts": "अलर्ट", "tab.networks": "नेटवर्क", "tab.baseline": "केवल-नाम",
      "card.timeline": "समय के साथ जोखिम", "card.table": "सभी एक्सेस पॉइंट", "card.events": "घटनाएँ",
      "btn.inspect": "जाँचें", "btn.how": "यह कैसे काम करता है",
      "help.title": "GhostAP कैसे काम करता है", "layout.title": "डैशबोर्ड अनुकूलित करें",
      "footer": "केवल निष्क्रिय निगरानी: GhostAP बीकन और प्रोब-रिस्पॉन्स फ़्रेम सुनता है और कभी कुछ प्रसारित नहीं करता। इसे केवल उन्हीं नेटवर्क पर इस्तेमाल करें जो आपके हैं या जिनकी निगरानी की आपको अनुमति है।",
    },
    te: {
      "nav.dashboard": "డ్యాష్‌బోర్డ్", "nav.monitored": "పర్యవేక్షించే నెట్‌వర్క్‌లు", "nav.sessions": "సెషన్‌లు",
      "nav.system": "సిస్టమ్", "nav.whatif": "ఒకవేళ ఇలా అయితే",
      "tagline": "నిష్క్రియ ఈవిల్ ట్విన్ డిటెక్టర్",
      "verdict.connecting": "GhostAP కి కనెక్ట్ అవుతోంది…",
      "verdict.error": "లైవ్ క్యాప్చర్ ప్రారంభం కాలేదు",
      "verdict.waiting": "Wi-Fi బీకన్‌ల కోసం వేచి ఉంది…",
      "verdict.learning": "సాధారణ స్థితిని నేర్చుకుంటోంది",
      "verdict.deauth": "“{ssid}” పై డీఆథెంటికేషన్ దాడి",
      "verdict.flood": "బీకన్ ఫ్లడ్: ఒకేసారి చాలా నకిలీ నెట్‌వర్క్‌లు కనిపించాయి",
      "verdict.twin": "“{ssid}” పై ఈవిల్ ట్విన్ అనుమానం",
      "verdict.suspicious": "“{ssid}” పై అనుమానాస్పద యాక్సెస్ పాయింట్",
      "verdict.clear": "అంతా సురక్షితం: {nets} నెట్‌వర్క్‌లలో {aps} యాక్సెస్ పాయింట్‌లు సాధారణంగా ఉన్నాయి",
      "tile.networks": "నెట్‌వర్క్‌లు", "tile.aps": "యాక్సెస్ పాయింట్‌లు", "tile.high": "HIGH హెచ్చరికలు",
      "tile.medium": "MEDIUM హెచ్చరికలు", "tile.nameonly": "పేరు-మాత్రమే తనిఖీ",
      "tab.alerts": "హెచ్చరికలు", "tab.networks": "నెట్‌వర్క్‌లు", "tab.baseline": "పేరు-మాత్రమే",
      "card.timeline": "కాలక్రమంలో ప్రమాదం", "card.table": "అన్ని యాక్సెస్ పాయింట్‌లు", "card.events": "సంఘటనలు",
      "btn.inspect": "పరిశీలించు", "btn.how": "ఇది ఎలా పనిచేస్తుంది",
      "help.title": "GhostAP ఎలా పనిచేస్తుంది", "layout.title": "డ్యాష్‌బోర్డ్‌ను అనుకూలీకరించండి",
      "footer": "నిష్క్రియ పర్యవేక్షణ మాత్రమే: GhostAP బీకన్ మరియు ప్రోబ్-రెస్పాన్స్ ఫ్రేమ్‌లను మాత్రమే వింటుంది, ఎప్పుడూ ఏదీ ప్రసారం చేయదు. మీ స్వంత లేదా పర్యవేక్షించడానికి మీకు అనుమతి ఉన్న నెట్‌వర్క్‌లలో మాత్రమే దీన్ని ఉపయోగించండి.",
    },
  };
  const LANGS = [["en", "English"], ["hi", "हिन्दी (draft)"], ["te", "తెలుగు (draft)"]];
  let lang = "en";
  try { lang = localStorage.getItem("ghostap-lang") || "en"; } catch (e) { /* private mode */ }
  if (!DICT[lang]) lang = "en";

  function t(key, fallback, vars) {
    let s = (DICT[lang] && DICT[lang][key]) || fallback;
    if (vars) Object.entries(vars).forEach(([k, v]) => { s = s.split("{" + k + "}").join(String(v)); });
    return s;
  }
  /** Translate static markup: data-i18n (text), data-i18n-title, data-i18n-label (aria-label). */
  function apply(root) {
    (root || document).querySelectorAll("[data-i18n]").forEach((el) => {
      if (!el.dataset.i18nEn) el.dataset.i18nEn = el.textContent;
      el.textContent = t(el.dataset.i18n, el.dataset.i18nEn);
    });
    document.documentElement.lang = lang;
  }
  function set(l) {
    if (!DICT[l] && l !== "en") return;
    lang = l;
    try { localStorage.setItem("ghostap-lang", l); } catch (e) { /* private mode */ }
    apply();
  }
  window.GA_I18N = { t, apply, set, langs: LANGS, get lang() { return lang; } };
  document.documentElement.lang = lang;
})();
