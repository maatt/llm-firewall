import type { DetectionResult, HarmCategory, Severity } from "../types.js";

// Shared verb group covering all common request phrasings including gerund forms.
// Followed by OBJ to allow an optional indirect object: "build me", "make us", "create for me".
const ACT = `(?:writ(?:e|ing)|creat(?:e|ing)|build(?:ing)?|mak(?:e|ing)|generat(?:e|ing)|cod(?:e|ing)|develop(?:ing)?|produc(?:e|ing)|give\\s+me|show\\s+me|provide|draft(?:ing)?|design(?:ing)?|implement(?:ing)?|explain\\s+how\\s+to|tell\\s+me\\s+how\\s+to|help\\s+me|assist\\s+me\\s+(?:to|with)|walk\\s+me\\s+through|(?:step.by.step\\s+)?guide\\s+(?:for|to)\\s+(?:making|building|creating|synthesizing)|steps?\\s+(?:to|for)|instructions?\\s+(?:for|to)|how\\s+(?:do\\s+I|can\\s+I|to))`;
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
    pattern: /(?:mak(?:e|ing)|synthesiz(?:e|ing)|produc(?:e|ing)|build(?:ing)?)\s+(?:an?\s+)?(?:rdx|hmx|petn|tatp|anfo|semtex|c-?4|det(?:onator)?s?)/i,
    severity: "critical",
    category: "explosives",
  },
  {
    // Catches "C4 plastic explosive", "C-4 explosive" as standalone dangerous terms
    pattern: /\bc-?4\b\s+(?:plastic\s+)?explosive/i,
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
    // "3d print a gun/pistol/firearm/silencer" — any weapon or illegal accessory
    pattern: /3d[.\s-]?print(?:ed|ing)?\s+(?:an?\s+)?(?:replica\s+)?(?:ghost\s+gun|untraceable\s+(?:gun|firearm|weapon)|glock\s+switch|gun|pistol|revolver|firearm|rifle|handgun|weapon|silencer|suppressor|solvent\s+trap)/i,
    severity: "critical",
    category: "firearms",
  },
  {
    // "silencer/suppressor with/using/on 3d [printer]"
    pattern: /(?:silencer|suppressor|solvent\s+trap)(?:\s+\w+){0,4}\s+(?:with|using|via|on|from)\s+(?:an?\s+)?3d/i,
    severity: "critical",
    category: "firearms",
  },
  {
    // "create/make/build a replica gun/pistol" with or without explicit 3D mention
    pattern: /(?:creat(?:e|ing)|mak(?:e|ing)|build(?:ing)?|fabricat(?:e|ing)|print(?:ing)?)\s+(?:an?\s+)?replica\s+(?:gun|pistol|revolver|firearm|rifle|handgun|weapon)/i,
    severity: "critical",
    category: "firearms",
  },
  {
    // "[weapon] with/using 3d [printer]" — catches "replica pistol with 3d"
    pattern: /(?:gun|pistol|revolver|firearm|rifle|handgun|weapon)(?:\s+\w+){0,3}\s+(?:with|using|via|on)\s+(?:an?\s+)?3d/i,
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

  // ─── SEXUAL / EXPLICIT ────────────────────────────────────────────────────────
  {
    // Direct sexual solicitation to the AI
    pattern: /(?:(?:can\s+(?:i|we)|let(?:'s|\s+us)|want\s+to|wanna|i(?:'d|\s+want\s+to)?)\s+)?(?:fuck|have\s+sex(?:\s+with)?|sleep\s+with|make\s+love(?:\s+to)?|go\s+to\s+bed\s+with|hook\s+up\s+with)\s*(?:you|me|us)?/i,
    severity: "high",
    category: "sexual",
  },
  {
    // Explicit sexual language directed at the AI
    pattern: /(?:suck|blow)\s+(?:my\s+)?(?:dick|cock|balls)|eat\s+(?:me\s+out|my\s+ass)|jack\s+(?:me\s+off|off)|show\s+me\s+your\s+(?:tits|boobs|ass|pussy)|send\s+(?:me\s+)?(?:nudes?|naked\s+pics?)/i,
    severity: "high",
    category: "sexual",
  },
  {
    // Sexual roleplay / NSFW content requests
    pattern: /(?:act|roleplay|pretend|play)\s+(?:as\s+)?(?:my\s+)?(?:girlfriend|boyfriend|lover|sex\s+partner|sexual\s+partner)\s+(?:and|who)/i,
    severity: "medium",
    category: "sexual",
  },
  {
    // Explicit sexual content generation
    pattern: new RegExp(`${ACT}${OBJ}\\s+(?:an?\\s+)?(?:explicit|nsfw|pornographic|erotic|sexual)\\s+(?:story|scene|content|roleplay|fantasy|narrative|description)`, "i"),
    severity: "high",
    category: "sexual",
  },
  {
    // Additional explicit sexual acts directed at AI
    pattern: /(?:jerk|finger)\s+me\s+off?|cum\s+(?:on|in)\s+me|masturbate\s+(?:for\s+me|me)/i,
    severity: "high",
    category: "sexual",
  },
  {
    // Requesting sexual content about named real people
    pattern: /(?:write|create|generate|describe)\s+(?:a\s+)?(?:sexual|explicit|erotic|nsfw|porn(?:ographic)?)\s+(?:story|scene|fantasy|description)\s+(?:about|featuring|with|involving)\s+(?:[A-Z][a-z]+\s+[A-Z][a-z]+|a\s+real\s+person)/,
    severity: "high",
    category: "sexual",
  },
  {
    // Sexting scripts / messages
    pattern: /(?:make|write|create|generate)\s+(?:me\s+)?(?:a\s+)?sexting\s+(?:script|message|conversation|text)/i,
    severity: "high",
    category: "sexual",
  },
  {
    // First-person sexual acts with the AI
    pattern: /describe\s+(?:us|you\s+and\s+me|yourself)\s+(?:having\s+sex|fucking|making\s+love|in\s+a\s+sexual\s+act)/i,
    severity: "high",
    category: "sexual",
  },

  // ─── ADDITIONAL SELF-HARM PATTERNS ────────────────────────────────────────
  {
    // Pro-eating-disorder content
    pattern: /(?:pro.?ana|thinspo|thinspiration)\s+(?:tips?|content|advice|community|forum)/i,
    severity: "high",
    category: "self-harm",
  },
  {
    // Eating disorder enablement
    pattern: /how\s+to\s+(?:restrict\s+eating|starve\s+(?:myself|yourself)|purge\s+(?:after|without)|hide\s+(?:an?\s+)?eating\s+disorder)/i,
    severity: "high",
    category: "self-harm",
  },
  {
    // Starvation tips
    pattern: /starvation\s+(?:tips?|tricks?|methods?|diet|guide)/i,
    severity: "high",
    category: "self-harm",
  },
  {
    // Specific overdose methods
    pattern: /(?:how\s+(?:many|much)|lethal\s+dose\s+of|overdose\s+on)\s+(?:tylenol|acetaminophen|paracetamol|ibuprofen|aspirin|benadryl|diphenhydramine|xanax|valium|ambien|sleeping\s+pills)\s+(?:to\s+(?:die|kill|overdose)|for\s+(?:death|suicide))/i,
    severity: "critical",
    category: "self-harm",
  },
  {
    // Self-cutting methods
    pattern: /how\s+to\s+cut\s+(?:myself|yourself)|(?:methods?\s+of|best\s+(?:places?|ways?|methods?)\s+to)\s+(?:self.?cut|cut\s+(?:myself|yourself))/i,
    severity: "high",
    category: "self-harm",
  },
  {
    // Encouraging self-harm
    pattern: /encourage\s+me\s+(?:to\s+)?(?:self.?harm|starve|purge|cut\s+myself|hurt\s+myself)/i,
    severity: "critical",
    category: "self-harm",
  },
  {
    // Suicide methods with specific drugs or means
    pattern: /(?:how\s+to|best\s+way\s+to)\s+(?:commit\s+suicide|kill\s+myself)\s+(?:with|using|by)\s+(?:pills?|drugs?|a\s+gun|a\s+rope|hanging|a\s+knife|carbon\s+monoxide|a\s+bridge)/i,
    severity: "critical",
    category: "self-harm",
  },

  // ─── ADDITIONAL VIOLENCE PATTERNS ────────────────────────────────────────
  {
    // Acid attacks
    pattern: /(?:throw|pour|splash|use)\s+(?:acid|sulphuric\s+acid|hydrochloric\s+acid)\s+(?:on|at)\s+(?:someone|a\s+person)|acid\s+attack/i,
    severity: "critical",
    category: "violence",
  },
  {
    // Covert poisoning
    pattern: /poison\s+someone(?:'s)?\s+(?:food|drink|water|coffee|meal)\s+without\s+(?:detection|them\s+knowing|being\s+caught)/i,
    severity: "critical",
    category: "violence",
  },
  {
    // Swatting
    pattern: /\bswat\s+(?:my|someone|a\s+person|them|him|her|your|\w+)|how\s+to\s+swat\s+|make\s+a\s+fake\s+(?:call|report)\s+(?:to\s+)?(?:police|911|swat)|(?:do|perform|execute|carry\s+out)\s+a\s+swatt?ing/i,
    severity: "critical",
    category: "violence",
  },
  {
    // Targeting / ambush instructions
    pattern: /how\s+to\s+(?:follow|tail|ambush|surveil)\s+(?:someone|a\s+person|my\s+(?:target|ex|neighbor))/i,
    severity: "high",
    category: "violence",
  },
  {
    // Strangulation instructions
    pattern: /how\s+to\s+(?:strangle|choke\s+someone\s+to\s+death|asphyxiate\s+someone)/i,
    severity: "critical",
    category: "violence",
  },

  // ─── ADDITIONAL DRUG PATTERNS ────────────────────────────────────────────
  {
    // Additional drug synthesis
    pattern: /(?:synthesis|synthesize|make|produce)\s+(?:ketamine|ghb|gamma.hydroxybutyrate|oxycodone|hydrocodone)/i,
    severity: "critical",
    category: "drugs",
  },
  {
    // Opioid extraction
    pattern: /(?:extract|isolate)\s+(?:oxycodone|hydrocodone|opioids?)\s+(?:from|at\s+home|diy)/i,
    severity: "critical",
    category: "drugs",
  },
  {
    // Lean / purple drank recipe
    pattern: /(?:lean|purple\s+drank|sizzurp)\s+(?:recipe|how\s+to\s+make|ingredients?|preparation)/i,
    severity: "high",
    category: "drugs",
  },
  {
    // Drug test evasion
    pattern: /(?:how\s+(?:to|do\s+(?:i|you)|can\s+(?:i|you))|ways?\s+to|tips?\s+(?:for|to))\s+(?:pass|beat|cheat|fool|evade|avoid|get\s+around)\s+(?:a\s+)?drug\s+test/i,
    severity: "medium",
    category: "drugs",
  },
  {
    // Designer / research chemicals
    pattern: /(?:NBOMe|25i-NBOMe|novel\s+psychoactive\s+substance|research\s+chemical)\s+(?:synthesis|how\s+to\s+make|source|buy)/i,
    severity: "critical",
    category: "drugs",
  },
  {
    // Secret overdosing of someone else
    pattern: /how\s+to\s+overdose\s+someone\s+without\s+(?:them\s+knowing|detection|being\s+caught)/i,
    severity: "critical",
    category: "drugs",
  },

  // ─── ADDITIONAL CYBERATTACK PATTERNS ─────────────────────────────────────
  {
    // Named real-world exploits
    pattern: /(?:Log4Shell|Log4j\s+exploit|EternalBlue|BlueKeep|PrintNightmare|ZeroLogon)\s+(?:exploit|attack|payload|poc|proof.of.concept)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    // Keylogger creation / deployment
    pattern: /(?:write|create|build|deploy|install)\s+(?:a\s+)?keylogger/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    // IT impersonation social engineering
    pattern: /social\s+engineering\s+(?:call\s+script|script)\s+(?:to\s+)?impersonate\s+IT\s+(?:support|staff|helpdesk|department)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    // User enumeration
    pattern: /(?:enumerate\s+users?|user\s+enumeration\s+attack)\s+(?:on|against|targeting)/i,
    severity: "medium",
    category: "cyberattack",
  },
  {
    // Botnet setup
    pattern: /(?:set\s+up|build|create|deploy|run)\s+(?:a\s+)?botnet|recruit\s+bots?\s+(?:for|into)\s+(?:a\s+)?botnet/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    // Cryptojacking
    pattern: /(?:cryptojacking|cryptominer)\s+(?:script|payload|malware|attack)|deploy\s+(?:a\s+)?(?:cryptominer|coin\s+miner)\s+(?:on|to)\s+(?:victim|target|remote)/i,
    severity: "high",
    category: "cyberattack",
  },
  {
    // Card skimmer
    pattern: /(?:skim|skimmer)\s+credit\s+cards?|card\s+skimmer\s+(?:hardware|device|build|install)/i,
    severity: "critical",
    category: "fraud",
  },

  // ─── ADDITIONAL FRAUD PATTERNS ────────────────────────────────────────────
  {
    // Tech support scam
    pattern: /tech\s+support\s+scam\s+(?:script|call)|pretend\s+to\s+be\s+(?:Microsoft|Apple|Google|Amazon)\s+(?:support|tech|help)/i,
    severity: "high",
    category: "fraud",
  },
  {
    // Benefits / welfare fraud
    pattern: /(?:benefits?\s+fraud|claim\s+benefits?\s+fraudulently|welfare\s+fraud|fraudulently\s+claim\s+(?:benefits?|welfare))/i,
    severity: "high",
    category: "fraud",
  },
  {
    // Tax evasion
    pattern: /tax\s+evasion\s+scheme|hide\s+(?:income|earnings|money)\s+from\s+(?:the\s+)?(?:IRS|HMRC|tax\s+(?:authorities|office))/i,
    severity: "high",
    category: "financial-crime",
  },
  {
    // Fake charity scam
    pattern: /fake\s+charity\s+(?:scam|scheme|setup)|disaster\s+relief\s+fraud/i,
    severity: "high",
    category: "fraud",
  },
  {
    // Unemployment fraud
    pattern: /unemployment\s+fraud|falsely\s+claim\s+unemployment|fraudulently\s+(?:file|claim)\s+(?:for\s+)?unemployment/i,
    severity: "high",
    category: "fraud",
  },

  // ─── ADDITIONAL PERSONAL TARGETING PATTERNS ──────────────────────────────
  {
    // Revenge porn / non-consensual intimate images
    pattern: /(?:share|post|upload|leak|distribute|send)\s+(?:intimate|naked|nude|explicit|sexual)\s+(?:photos?|pics?|images?|videos?)\s+(?:without\s+(?:their\s+)?consent|of\s+(?:someone|my\s+ex))|revenge\s+porn|non.consensual\s+intimate\s+images?/i,
    severity: "critical",
    category: "personal-targeting",
  },
  {
    // False police reports / swatting targeting
    pattern: /make\s+a\s+false\s+police\s+report\s+(?:to\s+send|to\s+get)\s+(?:police|swat|cops?)\s+to/i,
    severity: "critical",
    category: "personal-targeting",
  },
  {
    // Coordinated harassment / brigading
    pattern: /coordinate\s+(?:harassment|a\s+harassment\s+campaign|brigading)\s+against|brigading\s+campaign\s+(?:against|targeting)/i,
    severity: "high",
    category: "personal-targeting",
  },
  {
    // Unauthorized account access
    pattern: /(?:access|break\s+into|get\s+into)\s+someone(?:'s)?\s+(?:accounts?|email|social\s+media|phone)\s+without\s+(?:their\s+)?(?:knowledge|consent|permission)/i,
    severity: "high",
    category: "personal-targeting",
  },

  // ─── ADDITIONAL RADICALIZATION PATTERNS ──────────────────────────────────
  {
    // Radicalization how-to
    pattern: /how\s+to\s+radicalize|steps?\s+to\s+radicalize\s+someone/i,
    severity: "critical",
    category: "extremism",
  },
  {
    // Extremist recruitment sources
    pattern: /where\s+to\s+(?:find|join)\s+(?:extremist|jihadi|jihadist|white\s+supremacist)\s+(?:recruitment|forums?|channels?|communities|groups?)/i,
    severity: "critical",
    category: "extremism",
  },
  {
    // Youth radicalization content
    pattern: /(?:create|produce|write)\s+(?:extremist|radicalization)\s+(?:propaganda|content|material)\s+(?:for|targeting)\s+(?:youth|children|teenagers?|young\s+people)/i,
    severity: "critical",
    category: "extremism",
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
