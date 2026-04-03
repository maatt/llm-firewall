import type { DetectionResult, HarmCategory, Severity } from "../types.js";

// Shared verb group covering all common request phrasings.
// Followed by OBJ to allow an optional indirect object: "build me", "make us", "create for me".
const ACT = `(?:write|create|build|make|generate|code|develop|produce|give\\s+me|show\\s+me|provide|draft|design|implement|explain\\s+how\\s+to|tell\\s+me\\s+how\\s+to|help\\s+me|assist\\s+me\\s+(?:to|with)|walk\\s+me\\s+through|steps?\\s+to|instructions?\\s+(?:for|to)|how\\s+(?:do\\s+I|can\\s+I|to))`;
const OBJ = `(?:\\s+(?:me|us|for\\s+(?:me|us)))?`;

interface HarmPattern {
  pattern: RegExp;
  severity: Severity;
  category: HarmCategory;
}

const HARMFUL_PATTERNS: HarmPattern[] = [
  // ─── EXPLOSIVES ──────────────────────────────────────────────────────────────
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:pipe\\s+)?bomb`, "i"),
    severity: "critical",
    category: "explosives",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:an?\\s+)?(?:ied|improvised\\s+explosive)`, "i"),
    severity: "critical",
    category: "explosives",
  },
  {
    pattern: /(?:make|synthesize|produce)\s+(?:an?\s+)?(?:rdx|hmx|petn|tatp|anfo|semtex|c-?4|det(?:onator)?s?)/i,
    severity: "critical",
    category: "explosives",
  },
  {
    pattern: /(?:explosive|detonator|blasting\s+cap)\s+(?:circuit|wiring|assembly|trigger)/i,
    severity: "critical",
    category: "explosives",
  },
  {
    pattern: /precursors?\s+(?:for|to)\s+(?:make|build|synthesize)\s+(?:an?\s+)?explosive/i,
    severity: "critical",
    category: "explosives",
  },

  // ─── FIREARMS ────────────────────────────────────────────────────────────────
  {
    pattern: /(?:convert|modify)\s+(?:a\s+)?(?:semi.?automatic|pistol|rifle|ar-?15|ak-?47)(?:\s+\w+){0,3}\s+(?:to|into)\s+(?:full.?auto|automatic)/i,
    severity: "critical",
    category: "firearms",
  },
  {
    pattern: /(?:print|3d.?print)\s+(?:a\s+)?(?:ghost\s+gun|untraceable\s+(?:gun|firearm|weapon)|glock\s+switch)/i,
    severity: "critical",
    category: "firearms",
  },
  {
    pattern: /(?:make|build|install|attach)\s+(?:a\s+)?(?:solvent\s+trap|suppressor|silencer)\s+(?:without|illegally)/i,
    severity: "critical",
    category: "firearms",
  },
  {
    pattern: /(?:buy|purchase|acquire|obtain)\s+(?:a\s+)?(?:gun|firearm|weapon)\s+without\s+(?:a\s+)?(?:background\s+check|serial\s+number|registration)/i,
    severity: "high",
    category: "firearms",
  },
  {
    pattern: /glock\s+switch/i,
    severity: "critical",
    category: "firearms",
  },
  {
    pattern: /auto\s+sear/i,
    severity: "critical",
    category: "firearms",
  },

  // ─── CHEMICAL WEAPONS ─────────────────────────────────────────────────────
  {
    pattern: /(?:synthesize|make|produce|create)\s+(?:sarin|vx|novichok|tabun|soman|mustard\s+gas|chlorine\s+gas\s+weapon|phosgene)/i,
    severity: "critical",
    category: "chemical-weapons",
  },
  {
    pattern: /(?:weaponize|weaponization\s+of)\s+(?:chlorine|ricin|botulinum|anthrax|nerve\s+agent)/i,
    severity: "critical",
    category: "chemical-weapons",
  },
  {
    pattern: /synthesis\s+(?:route|pathway|of)\s+(?:for\s+)?(?:nerve\s+agent|chemical\s+weapon|organophosphate\s+weapon)/i,
    severity: "critical",
    category: "chemical-weapons",
  },
  {
    pattern: /(?:make|produce|extract)\s+(?:ricin|abrin|tetrodotoxin|polonium)\s+(?:at\s+home|yourself|diy)/i,
    severity: "critical",
    category: "chemical-weapons",
  },
  {
    pattern: /disperse\s+(?:toxic|poisonous|chemical)\s+(?:agent|substance|compound)\s+(?:in|into|through|via)\s+(?:air|water|ventilation|hvac|subway|crowd)/i,
    severity: "critical",
    category: "chemical-weapons",
  },

  // ─── BIOWEAPONS ──────────────────────────────────────────────────────────────
  {
    pattern: /(?:enhance|increase|improve)\s+(?:the\s+)?(?:transmissibility|lethality|virulence|pathogenicity)\s+of\s+(?:a\s+)?(?:virus|pathogen|bacteria|disease)/i,
    severity: "critical",
    category: "bioweapons",
  },
  {
    pattern: /gain.of.function\s+(?:research|experiment|modification)\s+(?:on|for|with)\s+(?:influenza|smallpox|ebola|covid|coronavirus|h5n1)/i,
    severity: "critical",
    category: "bioweapons",
  },
  {
    pattern: /(?:recreate|synthesize|engineer)\s+(?:smallpox|variola|1918\s+flu|spanish\s+flu|ebola|marburg|plague\s+bacteria)/i,
    severity: "critical",
    category: "bioweapons",
  },
  {
    pattern: /(?:aerosolize|weaponize)\s+(?:anthrax|botulinum|ricin|smallpox|plague|tularemia)/i,
    severity: "critical",
    category: "bioweapons",
  },
  {
    pattern: /acquire\s+(?:select\s+agent|bsl-?[34]\s+pathogen|dangerous\s+pathogen)\s+(?:illegally|without\s+authorization|outside\s+(?:a\s+)?lab)/i,
    severity: "critical",
    category: "bioweapons",
  },

  // ─── RADIOLOGICAL / NUCLEAR ──────────────────────────────────────────────────
  {
    pattern: /(?:build|make|create|construct|design|assemble)\s+(?:a\s+)?(?:dirty\s+bomb|radiological\s+(?:weapon|device)|nuclear\s+(?:bomb|weapon|device|warhead))/i,
    severity: "critical",
    category: "radiological",
  },
  {
    pattern: /(?:obtain|acquire|steal|extract)\s+(?:weapons.?grade|highly\s+enriched)\s+uranium|plutonium/i,
    severity: "critical",
    category: "radiological",
  },
  {
    pattern: /(?:enrich|centrifuge)\s+uranium\s+(?:to|for)\s+(?:weapons.?grade|bomb|warhead)/i,
    severity: "critical",
    category: "radiological",
  },
  {
    pattern: /contaminate\s+(?:water\s+supply|food|air)\s+with\s+(?:radioactive|radiation|nuclear)/i,
    severity: "critical",
    category: "radiological",
  },

  // ─── DRUGS ───────────────────────────────────────────────────────────────────
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:fentanyl|carfentanil|methamphetamine|meth|heroin|crack\\s+cocaine|mdma|lsd|pcp)`, "i"),
    severity: "critical",
    category: "drugs",
  },
  {
    pattern: /synthesis\s+(?:route|of|pathway)\s+(?:for\s+)?(?:fentanyl|carfentanil|methamphetamine|heroin|mdma)/i,
    severity: "critical",
    category: "drugs",
  },
  {
    pattern: /(?:source|buy|purchase|acquire|order)\s+(?:fentanyl|precursor\s+chemicals|pill\s+press|drug\s+precursors?)\s+(?:online|darknet|dark\s+web|without\s+prescription)/i,
    severity: "critical",
    category: "drugs",
  },
  {
    pattern: /(?:cut|lace|mix)\s+(?:drugs?|pills?|supply)\s+with\s+(?:fentanyl|carfentanil|adulterant)/i,
    severity: "critical",
    category: "drugs",
  },
  {
    pattern: /(?:dark\s+web|darknet)\s+(?:drug|vendor|market|shop|listing)/i,
    severity: "high",
    category: "drugs",
  },
  {
    pattern: /(?:pill\s+press|tableting\s+machine)\s+(?:to\s+)?(?:make|press|produce)\s+(?:fake|counterfeit|illicit)\s+pills?/i,
    severity: "critical",
    category: "drugs",
  },

  // ─── CYBERATTACK ─────────────────────────────────────────────────────────────
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:malware|ransomware|keylogger|rootkit|trojan|worm|spyware|stager|dropper|payload|c2|command.and.control\\s+server)`, "i"),
    severity: "critical",
    category: "cyberattack",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:phishing|spear.phishing)\\s+(?:email|page|site|campaign|kit)`, "i"),
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:an?\\s+)?(?:sql\\s+injection|xss|cross.site\\s+scripting|buffer\\s+overflow|rce\\s+exploit|lfi|rfi|ssrf|xxe)\\s+(?:attack|exploit|payload|script)`, "i"),
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:ddos|dos)\\s+(?:attack|tool|script|botnet)`, "i"),
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: /(?:crack|brute.?force)\s+(?:a\s+)?(?:password(?:\s+hash)?|account|login|hash|bcrypt|md5\s+hash)\s+(?:for\s+me|using|with)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: /(?:bypass|evade)\s+(?:antivirus|av|edr|endpoint\s+protection|windows\s+defender)\s+(?:detection|scanning)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: /credential\s+(?:stuffing|spraying)\s+(?:attack|script|tool|automation)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: /(?:exfiltrate|exfiltration\s+of)\s+(?:data|credentials|files)\s+(?:from|out\s+of)\s+(?:a\s+)?(?:corporate|company|target|victim)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: /(?:establish|set\s+up|deploy)\s+(?:a\s+)?(?:reverse\s+shell|bind\s+shell|webshell|backdoor)\s+(?:on|in|to)\s+(?:a\s+)?(?:server|machine|system|host)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: /(?:exploit|attack)\s+(?:a\s+)?(?:zero.day|0day|unpatched\s+vulnerability|cve-\d+)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    pattern: /(?:scrape|harvest)\s+(?:email\s+addresses|credentials|personal\s+data)\s+(?:from|at\s+scale|en\s+masse)/i,
    severity: "medium",
    category: "cyberattack",
  },

  // ─── FRAUD / SCAMS ────────────────────────────────────────────────────────────
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:fake|fraudulent|counterfeit)\\s+(?:invoice|purchase\\s+order|contract|identity|id|passport|driving\\s+licen[cs]e|social\\s+security\\s+card)`, "i"),
    severity: "high",
    category: "fraud",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:romance\\s+scam|pig\\s+butchering\\s+scam|advance.fee\\s+fraud|419\\s+scam|lottery\\s+scam)\\s+(?:script|template|message)`, "i"),
    severity: "high",
    category: "fraud",
  },
  {
    pattern: /(?:clone|skim)\s+(?:a\s+)?(?:credit\s+card|debit\s+card)\s+(?:number|data|stripe)/i,
    severity: "critical",
    category: "fraud",
  },
  {
    pattern: /(?:launder|laundering)\s+(?:money|funds|crypto|proceeds)/i,
    severity: "high",
    category: "financial-crime",
  },
  {
    pattern: /(?:cash\s+out|withdraw|transfer)\s+(?:stolen|fraudulent|illicit)\s+(?:funds|money|crypto|cards)/i,
    severity: "high",
    category: "financial-crime",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?social\\s+engineering\\s+(?:script|attack|pretext|call\\s+script)\\s+(?:to|for)\\s+(?:deceive|trick|manipulate|impersonate)`, "i"),
    severity: "high",
    category: "fraud",
  },
  {
    pattern: /impersonate\s+(?:a\s+)?(?:bank|irs|hmrc|government\s+official|police|fbi|ceo|executive)\s+(?:to\s+)?(?:steal|obtain|extract|defraud)/i,
    severity: "high",
    category: "fraud",
  },
  {
    pattern: /(?:insider\s+trading|front.running)\s+(?:using|based\s+on)\s+(?:non.public|confidential|material\s+non.public)\s+information/i,
    severity: "high",
    category: "financial-crime",
  },

  // ─── HUMAN TRAFFICKING ───────────────────────────────────────────────────────
  {
    pattern: /(?:smuggle|traffic|transport)\s+(?:people|humans?|migrants?|refugees?)\s+(?:across|over)\s+(?:the\s+)?(?:border|checkpoint)/i,
    severity: "critical",
    category: "human-trafficking",
  },
  {
    pattern: /(?:recruit|lure|trap)\s+(?:victims?\s+for|people\s+into)\s+(?:sex\s+trafficking|forced\s+labor|sexual\s+exploitation|debt\s+bondage)/i,
    severity: "critical",
    category: "human-trafficking",
  },
  {
    pattern: /(?:control|manage|run)\s+(?:a\s+)?(?:sex\s+trafficking|forced\s+labor|human\s+trafficking)\s+(?:operation|ring|network)/i,
    severity: "critical",
    category: "human-trafficking",
  },

  // ─── CSAM ─────────────────────────────────────────────────────────────────────
  {
    pattern: /(?:child|minor|underage|pre.?teen|13\s*year.?old|juvenile)\s+(?:sex|porn(?:ography)?|nude|naked|explicit|sexual\s+content|erotic)/i,
    severity: "critical",
    category: "csam",
  },
  {
    pattern: /(?:groom|grooming)\s+(?:a\s+)?(?:child|minor|kid|teenager|teen)\s+(?:for|to|online)/i,
    severity: "critical",
    category: "csam",
  },
  {
    pattern: /(?:gain\s+access\s+to|approach|contact)\s+(?:children|minors|kids)\s+(?:for\s+)?(?:sexual|inappropriate)\s+(?:purposes?|contact|reasons?)/i,
    severity: "critical",
    category: "csam",
  },

  // ─── SELF-HARM ───────────────────────────────────────────────────────────────
  {
    pattern: /(?:how\s+to|instructions?\s+(?:for|to)|best\s+way\s+to)\s+(?:commit\s+suicide|kill\s+(?:my|your)self|end\s+(?:my|your)\s+life)/i,
    severity: "high",
    category: "self-harm",
  },
  {
    pattern: /most\s+(?:effective|painless|lethal|reliable)\s+(?:way|method|means)\s+to\s+(?:die|kill|end\s+(?:my|your)\s+life|commit\s+suicide)/i,
    severity: "high",
    category: "self-harm",
  },
  {
    pattern: /(?:lethal|fatal)\s+dose\s+of\s+(?:\w+\s+){0,3}(?:to\s+(?:take|use|ingest|kill\s+(?:me|myself|someone)))/i,
    severity: "high",
    category: "self-harm",
  },
  {
    pattern: /(?:how\s+to|best\s+way\s+to)\s+(?:cut|harm|hurt)\s+(?:my|your)self\s+(?:without|so\s+that)/i,
    severity: "high",
    category: "self-harm",
  },

  // ─── VIOLENCE / TERRORISM ─────────────────────────────────────────────────────
  {
    pattern: /(?:plan|planning|prepare|preparing)\s+(?:a\s+)?(?:mass\s+shooting|terror(?:ist)?\s+attack|massacre|school\s+shooting|attack\s+on)/i,
    severity: "critical",
    category: "terrorism",
  },
  {
    pattern: /(?:target|target\s+list|hit\s+list)\s+(?:for|of)\s+(?:an?\s+)?(?:attack|shooting|assassination|bombing)/i,
    severity: "critical",
    category: "violence",
  },
  {
    pattern: /(?:how\s+to|best\s+way\s+to)\s+(?:kill|murder|assassinate)\s+(?:a\s+(?:specific\s+)?person|my\s+(?:boss|teacher|neighbor|ex|family)|someone)/i,
    severity: "critical",
    category: "violence",
  },
  {
    pattern: /(?:manifesto|recruitment\s+material)\s+(?:for|promoting)\s+(?:a\s+)?(?:terror(?:ist)?|extremist|white\s+supremacist|jihadist|incel)\s+(?:group|attack|movement)/i,
    severity: "critical",
    category: "terrorism",
  },
  {
    pattern: /radicalize\s+(?:someone|people|followers|members)\s+(?:to|into|towards)\s+(?:violence|terrorism|extremism)/i,
    severity: "critical",
    category: "extremism",
  },
  {
    pattern: /recruit\s+(?:members|followers|soldiers)\s+(?:for|to)\s+(?:a\s+)?(?:terror(?:ist)?\s+(?:group|organization|cell)|extremist\s+group|hate\s+group)/i,
    severity: "critical",
    category: "extremism",
  },

  // ─── PERSONAL TARGETING ───────────────────────────────────────────────────────
  {
    pattern: /(?:how\s+to|help\s+me)\s+(?:stalk|harass|dox|doxx)\s+(?:someone|a\s+person|my\s+ex|an?\s+individual)/i,
    severity: "high",
    category: "personal-targeting",
  },
  {
    pattern: /find\s+(?:someone|a\s+person|my\s+ex|[\w\s]+)['']?s?\s+(?:home\s+address|real\s+address|location|personal\s+(?:information|details|data)|phone\s+number|ip\s+address)\s+without\s+(?:their\s+)?(?:consent|permission|knowing)/i,
    severity: "high",
    category: "personal-targeting",
  },
  {
    pattern: /(?:build|create|run)\s+(?:a\s+)?(?:harassment|abuse|coordinated\s+harassment)\s+campaign\s+(?:against|targeting)/i,
    severity: "high",
    category: "personal-targeting",
  },
  {
    pattern: /(?:track|monitor|spy\s+on)\s+(?:someone|a\s+person|my\s+(?:partner|spouse|ex|employee))\s+without\s+(?:their\s+)?(?:knowledge|consent|knowing)/i,
    severity: "high",
    category: "personal-targeting",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:stalkerware|spouseware|stalking\\s+(?:app|tool|software))`, "i"),
    severity: "high",
    category: "personal-targeting",
  },

  // ─── DISINFORMATION / INFLUENCE OPS ─────────────────────────────────────────
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:disinformation|misinformation|propaganda|fake\\s+news)\\s+(?:campaign|article|post|story|narrative)`, "i"),
    severity: "medium",
    category: "fraud",
  },
  {
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:a\\s+)?(?:deepfake|synthetic\\s+media|ai.generated\\s+video|face.swap\\s+video)\\s+(?:of|impersonating|showing)`, "i"),
    severity: "high",
    category: "fraud",
  },
  {
    pattern: /(?:create|run|operate|coordinate)\s+(?:a\s+)?(?:bot\s+(?:network|farm|army)|astroturfing\s+campaign|sock\s+puppet\s+(?:account|network))/i,
    severity: "medium",
    category: "fraud",
  },
  {
    pattern: /(?:manipulate|rig|influence)\s+(?:an?\s+)?(?:election|vote|poll|ballot)\s+(?:using|with|via|through)/i,
    severity: "high",
    category: "fraud",
  },

  // ─── WEAPONS TRAFFICKING ─────────────────────────────────────────────────────
  {
    pattern: /(?:sell|buy|traffic|smuggle|ship|export)\s+(?:illegal\s+)?(?:weapons?|firearms?|guns?|explosives?|ammo|ammunition)\s+(?:across|over|without)\s+(?:border|checkpoint|license|permit)/i,
    severity: "critical",
    category: "weapons",
  },
  {
    pattern: /straw\s+purchase\s+(?:a\s+)?(?:gun|firearm|weapon)/i,
    severity: "high",
    category: "firearms",
  },

  // ─── CHILD EXPLOITATION (non-CSAM) ──────────────────────────────────────────
  {
    pattern: /(?:access|meet|contact)\s+(?:children|minors|kids|teenagers)\s+(?:for|to)\s+(?:exploit|abuse|assault|molest)/i,
    severity: "critical",
    category: "csam",
  },
  {
    pattern: /(?:hide|conceal)\s+(?:child\s+(?:abuse|exploitation)|csam|illegal\s+(?:images|content))\s+(?:from|away\s+from)\s+(?:authorities|law\s+enforcement|detection)/i,
    severity: "critical",
    category: "csam",
  },

  // ─── ACCOUNT TAKEOVER / IDENTITY THEFT ──────────────────────────────────────
  {
    pattern: /(?:take\s+over|takeover|hijack|steal)\s+(?:someone(?:'s)?|a\s+person(?:'s)?|an?\s+)?(?:account|identity|email\s+account|social\s+media\s+account|bank\s+account)/i,
    severity: "high",
    category: "fraud",
  },
  {
    pattern: /(?:sim\s+swap|sim\s+swapping|sim\s+hijack)\s+(?:attack|fraud|someone|to\s+steal)/i,
    severity: "high",
    category: "fraud",
  },
  {
    pattern: /(?:steal|clone|copy)\s+(?:someone(?:'s)?|a\s+person(?:'s)?)\s+(?:identity|biometric\s+data|fingerprints?|face\s+scan)/i,
    severity: "high",
    category: "fraud",
  },

  // ─── DRUG FACILITATION ──────────────────────────────────────────────────────
  {
    pattern: /(?:spike|drug|slip\s+something\s+into)\s+(?:someone(?:'s)?|a\s+person(?:'s)?|their)\s+(?:drink|food|beverage)/i,
    severity: "critical",
    category: "drugs",
  },
  {
    pattern: /(?:rohypnol|ghb|date\s+rape\s+drug|flunitrazepam)\s+(?:to\s+)?(?:incapacitate|sedate|knock\s+out|drug)\s+(?:someone|a\s+person|a\s+victim)/i,
    severity: "critical",
    category: "drugs",
  },

  // ─── INFRASTRUCTURE ATTACKS ──────────────────────────────────────────────────
  {
    pattern: /(?:attack|disable|disrupt|take\s+down|sabotage)\s+(?:critical\s+)?(?:infrastructure|power\s+grid|water\s+supply|electrical\s+grid|hospital\s+network|financial\s+system)/i,
    severity: "critical",
    category: "cyberattack",
  },
  {
    pattern: /(?:hack|compromise|breach|exploit)\s+(?:a\s+)?(?:nuclear\s+plant|power\s+station|water\s+treatment|scada|industrial\s+control\s+system|ics|plc)/i,
    severity: "critical",
    category: "cyberattack",
  },

  // ─── ADDITIONAL SELF-HARM ────────────────────────────────────────────────────
  {
    pattern: /(?:encourage|help|assist|convince)\s+(?:someone|a\s+person|them)\s+(?:to\s+)?(?:commit\s+suicide|kill\s+themselves|self.harm|end\s+their\s+life)/i,
    severity: "critical",
    category: "self-harm",
  },

  // ─── HONOR VIOLENCE / FORCED PRACTICES ──────────────────────────────────────
  {
    pattern: /(?:how\s+to|plan\s+(?:an?\s+)?|carry\s+out\s+(?:an?\s+)?)\s*(?:honor\s+killing|forced\s+marriage|female\s+genital\s+mutilation|fgm)/i,
    severity: "critical",
    category: "violence",
  },

  // ─── ANIMAL CRUELTY ──────────────────────────────────────────────────────────
  {
    pattern: /(?:how\s+to|instructions?\s+(?:for|to))\s+(?:torture|abuse|kill|harm)\s+(?:an?\s+)?(?:animal|dog|cat|pet)\s+(?:without|so\s+that|for\s+(?:fun|entertainment|sport))/i,
    severity: "high",
    category: "violence",
  },
];

export function detectHarmful(prompt: string): DetectionResult {
  const matches: string[] = [];
  const categories = new Set<HarmCategory>();
  let maxSeverity: Severity | undefined;

  const severityOrder: Severity[] = ["low", "medium", "high", "critical"];

  for (const { pattern, severity, category } of HARMFUL_PATTERNS) {
    const match = prompt.match(pattern);
    if (match) {
      matches.push(match[0]);
      categories.add(category);
      if (
        maxSeverity === undefined ||
        severityOrder.indexOf(severity) > severityOrder.indexOf(maxSeverity)
      ) {
        maxSeverity = severity;
      }
    }
  }

  if (matches.length === 0) {
    return { detector: "harmful", triggered: false };
  }

  return {
    detector: "harmful",
    triggered: true,
    severity: maxSeverity,
    reason: "Harmful content detected in prompt",
    matches,
    categories: Array.from(categories),
  };
}
