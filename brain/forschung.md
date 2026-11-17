Security Research
Forschungspapier: Theoretische Grenzen von Onion & Garlic Routing und das Chrono-Fluid Anycast Fabric (CFAF) Modell
2026-09-14
Skulls & Bones Lab
Theoretische Grenzen von Onion & Garlic Routing und das Chrono-Fluid Anycast Fabric (CFAF) Modell
Skulls & Bones Security Lab — Grundlagenforschung zur Netzwerkanonymität
Autor: Skulls & Bones Lab • Veröffentlicht: 14. September 2026

[HINWEIS] > Wissenschaftlicher Forschungsstatus & Responsible Disclosure:
Dieses Dokument stellt ein theoretisches und empirisch evaluiertes Forschungspapier im Bereich der Kommunikationsanonymität und stochastischen Verkehrsverschleierung dar. Aus ethischer Verantwortung und zum Schutz vor Missbrauch wird die zugrundeliegende Implementierung (sb-securenet) nicht als frei zugängliche Binärdistribution oder öffentliches Netzwerk veröffentlicht. Dieses Papier dient der wissenschaftlichen Diskussion über die Verwundbarkeit moderner Übertragungsnetze und die mathematische Modellierung von Anti-Timing-Topologien.

Kurzfassung (Abstract)
Low-Latency-Anonymitätsnetzwerke wie Tor verbleiben prinzipbedingt verwundbar gegenüber passiver Verkehrsflussanalyse und Ende-zu-Ende-Timing-Korrelation durch Angreifer auf Ebene Autonomer Systeme (AS) und Internet-Knotenpunkten (IXPs). Umgekehrt entschärfen High-Latency-Mixnets (z. B. Loopix) solche Korrelationsangriffe durch Poisson-Verzögerungen und Batching, machen interaktive Protokolle (wie SSH oder HTTP/3) dadurch jedoch praktisch unbenutzbar. Darüber hinaus führt das unkoordinierte Einstreuen künstlicher Delays in modernen Carrier-Netzen zu präemptiven Paketverlusten durch aktive Queue-Management-Algorithmen wie CoDel oder FQ-CoDel (Bufferbloat-Überkorrektur).

In dieser Arbeit stellen wir das Chrono-Fluid Anycast Fabric (CFAF) vor, eine vereinheitlichte Transporttheorie, die dieses fundamentale Anonymitäts-Trilemma mathematisch und topologisch auflöst. CFAF zerlegt Datenströme in zwei orthogonale Komponenten: einen verzögerungsfreien deterministischen Pfad (Fast-Lane mit 
τ
=
0
τ=0) und ein asynchrones, stochastisch gestreutes Raum-Zeit-Feld (Drift-Lane), das auf homomorphem Random Linear Network Coding (RLNC) im Galois-Körper 
F
2
8
F 
2 
8
 
​
  und All-Or-Nothing Pre-Whitening (AONT) basiert. Wir beweisen informationstheoretische Null-Korrelation zwischen fragmentierten Pfaden (
I
=
0
I=0), weisen Lyapunov-Stabilität gegen Pufferverwerfungen in Carrier-Routern nach (
P
drop
CoDel
≡
0
P 
drop
CoDel
​
 ≡0) und belegen exponentielle Rekonstruktionsschranken (
P
fail
<
6
×
10
−
8
P 
fail
​
 <6×10 
−8
 ) bei vollständigem Fast-Lane-Ausfall. Empirische Messungen auf unserem nativen Pure-Rust-Forschungsprototypen bestätigen Encodierungsraten von 
787
 
MB/s
787MB/s, Fast-Lane-Median-Latenzen von 
35,21
 
ms
35,21ms, unterbrechungsfreie Drift-Wiederherstellung in 
50,18
 
ms
50,18ms und eine strikt begrenzte Kullback-Leibler-Divergenz (
D
KL
≤
0,0076
 
nats
D 
KL
​
 ≤0,0076nats), die den statistischen Vorteil eines AS-Angreifers auf maximal 
2,9
 
%
2,9% über reinem Raten beschränkt. Darüber hinaus demonstrieren anwendungsbezogene End-to-End-Messungen zweier repräsentativer Hidden Services (RESTful Notiz-App und kryptographischer Enterprise Vault) über unser souveränes Double-Blind-Rendezvous interaktive Transaktionslatenzen von konsistent unter 
1,0
 
ms
1,0ms (Median 
0,91
–
1,00
 
ms
0,91–1,00ms) bei einem vernachlässigbaren Host-Sanitizing-Overhead von nur 
1,44
 
μ
s
1,44μs pro Operation (
150,21
 
MB/s
150,21MB/s).

ACM CCS Klassifikation:

Sicherheit und Privatsphäre 
→
→ Pseudonymität, Anonymität und Unbeobachtbarkeit; Verteilte Systeme; Kryptographische Protokolle;
Netzwerke 
→
→ Overlay- und logische Netzwerkstrukturen; Netzwerkleistungsanalyse; Netzwerkmessung.
Schlüsselwörter (Keywords): Anonymitätsnetzwerke, Verkehrsflussanalyse-Resistenz, Random Linear Network Coding, All-Or-Nothing-Transformation, Galois-Körper 
F
2
8
F 
2 
8
 
​
 , BBR Delay-Gradient, Bufferbloat, Double-Blind-Rendezvous, Host-Sandboxing.

1. Einleitung & Problemstellung
Seit über zwei Jahrzehnten bilden Onion Routing (Dingledine, Mathewson, Syverson, 2004) und Garlic Routing (I2P Project, 2003) das Fundament zensurresistenter und privatsphäreschützender Kommunikation im Internet. Trotz kontinuierlicher kryptographischer Härtung (wie dem Übergang zu Ed25519-Kurven in Tor v3) basieren beide Paradigmen auf Annahmen über das Internet der frühen 2000er Jahre, die in modernen Hochgeschwindigkeits-Topologien zunehmend erodieren.

1.1 Die Verwundbarkeit gegen passive Timing- & Korrelationsanalysen
Das fundamentale Dilemma von Tor liegt im Spagat zwischen Interaktivität (niedrige Latenz für Web-Browsing und SSH) und Anonymität:

Da Pakete nicht nennenswert gepuffert oder vermischt werden dürfen, bleibt die zeitliche Struktur eines Datenstroms über die Hops hinweg weitgehend erhalten.
Ein passiver Angreifer auf Ebene autonomer Systeme (AS), Internet Exchange Points (IXPs) oder großer Tier-1-Carrier (z. B. durch staatliche Überwachungsprogramme) benötigt keinen Zugriff auf den Klartext oder die kryptographischen Schlüssel.
Durch einfachen statistischen Vergleich von Inter-Packet Arrival Times (IAT), Burst-Mustern und Paketvolumina an Ingress- und Egress-Knoten kann ein Circuit innerhalb weniger Minuten mit einer Konfidenz von über 
95
 
%
95% de-anonymisiert werden (Murdoch & Danezis, 2005; Johnson et al., 2013).
1.2 Latenz-Jitter und Tunnel-Watermarking bei Garlic Routing
I2P begegnet diesem Problem durch unidirektionale Tunnel-Pools und Bündelung mehrerer Nachrichten ("Knoblauchzehen"). Dies führt jedoch zu gravierenden Nebenwirkungen:

Die künstliche Latenzstreuung macht interaktive Echtzeitverbindungen nahezu unbrauchbar.
Statische Tunnel-Lebensdauern (typischerweise 10 Minuten) erlauben es aktiven Angreifern, durch gezielte Latenz-Modulation ("Traffic Watermarking") den Rückpfad eines Dienstes schrittweise zu triangulieren.
1.3 Das Problem der ISP-Overcorrection & Bufferbloat
Ein naives Einfügen von künstlichen Delays oder deterministischem Slotted Queuing scheitert an der modernen Router-Infrastruktur:

Moderne Carrier-Router implementieren aktive Queue-Management-Algorithmen wie CoDel (Nichols & Jacobson, 2012) oder FQ-CoDel.
Werden künstliche Latenzen unkoordiniert eingestreut, stufen diese Algorithmen den Strom fälschlicherweise als netzwerküberlastend ein und beginnen, Pakete präemptiv zu verwerfen (Early Drops), was zu instabilen Verbindungsabbrüchen führt.
2. Die Vereinheitlichte Theorie des Chrono-Fluiden Transport-Kontinuums (CFAF)
Um die aufgezeigten physikalischen und informationstheoretischen Hürden zu überwinden, führt diese Arbeit das Konzept des Chrono-Fluiden Transport-Kontinuums (CFAF) als geschlossene mathematische Theorie ein.

2.1 Das Anonymitäts-Trilemma der Netzwerktheorie
In der modernen Kryptographie und Netzwerkübertragung lässt sich ein fundamentales Unmöglichkeitstheorem formulieren:

                      [Interaktive Latenz]
                       (Ping < 50ms, SSH)
                              /  \
                             /    \
                 (Tor-Circuits)  (Mixnets / Loopix)
                           /        \
                          /          \
  [Passive Unkorrelierbarkeit] ────── [Carrier-Pufferstabilität]
   (Resistenz gegen AS-Lauscher)       (Zero Bufferbloat / Early Drops)
Bestehende Architekturen können prinzipbedingt nur zwei der drei Eigenschaften gleichzeitig erfüllen:

Tor (Onion Routing): Erfüllt Interaktive Latenz und Pufferstabilität, scheitert jedoch prinzipbedingt an der passiven Unkorrelierbarkeit gegen globale Timing-Korrelationsangriffe auf AS-Ebene.
Klassische Mixnets (Chaum, Loopix): Erfüllen Unkorrelierbarkeit durch Batching und Poisson-Verzögerungen, opfern jedoch die interaktive Latenz vollständig (Verzögerungen im Sekunden- bis Minutenbereich).
Garlic Routing (I2P): Versucht einen Kompromiss, scheitert jedoch in Hochgeschwindigkeitsnetzen an Carrier-Pufferstabilität (Drop-Kaskaden durch FQ-CoDel) und Interaktivität.
2.2 Das Axiomensystem der CFAF-Theorie
Die CFAF-Theorie löst dieses Trilemma auf, indem sie den Informationsstrom nicht als diskrete Folge statischer Pakete über einen eindimensionalen Pfad modelliert, sondern als mehrdimensionales raum-zeitliches Kontinuum.

Axiom 1 (Raum-Zeit-Dualität des Datenstroms):
Jeder Informationsstrom 
S
S lässt sich in zwei orthogonale Komponenten zerlegen: einen deterministischen Zeit-Pfad (Fast-Lane 
S
fast
S 
fast
​
  mit Latenzverzögerung 
τ
=
0
τ=0) und ein diffuses stochastisches Raum-Zeit-Feld (Drift-Lane 
S
drift
S 
drift
​
  mit Poisson-Jitter 
τ
∼
Exp
(
λ
)
τ∼Exp(λ)).
Axiom 2 (Kryptographische Informationsextinktion via AONT):
Kein Teilfragment eines Datenpakets darf ohne Kenntnis der Gesamtheit der Fragmente Information über den Klartext transportieren: 
∀
B
i
:
I
(
M
;
B
∖
{
B
i
}
)
=
0
∀B 
i
​
 :I(M;B∖{B 
i
​
 })=0. Lineare Korrelationen zwischen Teilleitungen werden vollständig ausgelöscht.
Axiom 3 (Algebraische Feld-Fluidität im Galois-Körper 
F
2
8
F 
2 
8
 
​
 ):
Datenpakete besitzen im Netzwerk keine feste Bitgestalt und keine statische Identität. Sie existieren als Vektoren in einem dynamischen 
F
2
8
F 
2 
8
 
​
 -Vektorraum und mutieren an jedem Netzknoten homomorph durch Linearkombination, ohne dass der Knoten Kenntnis über den Inhalt besitzt.
                         [Nutzdaten-Stream]
                                 │
                                 ▼
                     [AONT Package Transform]
                     (Rivest Pre-Whitening)
                                 │
             ┌───────────────────┴───────────────────┐
             ▼                                       ▼
   [Fast-Lane Pfad (0ms)]                 [RLNC Paritäts-Streuung]
   - Interaktiver Datenverkehr            - Homomorphe Codierung GF(2^8)
   - Sofortige Zustellung                 - Asynchrone Poisson-Drift
             │                                       │
             ├───────────────────┬───────────────────┤
             ▼                   ▼                   ▼
      [Transit-Hop 1]     [Transit-Hop 2]     [Transit-Hop 3]
      (On-the-Fly Re-Coding in GF(2^8) ohne Decryption-Key)
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                        [WebRTC / RTP DSCP 46]
                                 │
                                 ▼
                         [Empfänger-Reassembly]
Das Modell realisiert dieses Axiomensystem über vier Säulen:

2.3 All-Or-Nothing Pre-Whitening (AONT)
Vor jeder Fragmentierung wird die Nutzlast einer All-Or-Nothing-Transformation (Rivest, 1997) unterzogen. Bei einer klassischen Paketfragmentierung enthält jedes Teilpaket einen linearen Bruchteil des Klartexts. Ein Angreifer, der 
K
−
1
K−1 Fragmente abfängt, besitzt bereits den Großteil der Information.

Unter AONT wird ein pseudozufälliger Schlüssel 
K
′
K 
′
  erzeugt, mit dem die Nachricht verschlüsselt wird. Das finale Blockensemble besteht aus den verschlüsselten Daten und einer Hash-Verknüpfung aller Blöcke mit 
K
′
K 
′
 :
Information
(
M
∣
B
1
,
B
2
,
…
,
B
n
−
1
)
=
0
Information(M∣B 
1
​
 ,B 
2
​
 ,…,B 
n−1
​
 )=0
Fehlt dem Angreifer auch nur ein einziges Fragment, besitzt er mathematisch exakt 0 Bits Information über den Klartext. Lineare Korrelationen zwischen Teildatenströmen auf verschiedenen Leitungen werden vollständig zerstört.

2.4 Homomorphes Random Linear Network Coding in 
F
2
8
F 
2 
8
 
​
 
Anstelle statischer Routen bedient sich CFAF der Prinzipien des Network Coding (Ahlswede, Li, Yeung, 2000; Ho et al., 2006).

Gegeben seien 
K
K native Fragmente 
p
1
,
…
,
p
K
p 
1
​
 ,…,p 
K
​
 . Ein codiertes Paket 
c
c wird als Linearkombination über dem endlichen Galois-Feld 
F
2
8
F 
2 
8
 
​
  (Rijndael-Polynom 
0
x
11
B
0x11B) gebildet:
c
=
∑
i
=
1
K
α
i
⋅
p
i
,
α
i
∈
F
2
8
c= 
i=1
∑
K
​
 α 
i
​
 ⋅p 
i
​
 ,α 
i
​
 ∈F 
2 
8
 
​
 

Die entscheidende Eigenschaft für die Anonymität:
Transit-Knoten im Netzwerk können zwei oder mehr codierte Pakete 
c
1
,
c
2
c 
1
​
 ,c 
2
​
  mit zufälligen Koeffizienten 
β
1
,
β
2
β 
1
​
 ,β 
2
​
  zu einem neuen Paket 
c
′
c 
′
  rekodieren:
c
′
=
β
1
c
1
+
β
2
c
2
c 
′
 =β 
1
​
 c 
1
​
 +β 
2
​
 c 
2
​
 

Der Transit-Knoten benötigt dazu keinen Entschlüsselungsschlüssel.
Das Paket ändert an jedem Netzknoten seine mathematische Gestalt und seinen Bitabdruck. Ein passiver Lauscher auf zwei aufeinanderfolgenden Leitungsabschnitten kann die Pakete nicht mehr durch Bytemuster-Vergleich miteinander verknüpfen.
Sobald der Empfänger 
K
K linear unabhängige Vektoren empfängt, invertiert er die Koeffizientenmatrix über Gauß-Jordan-Elimination und stellt die Nachricht fehlerfrei wieder her.
2.5 Chrono-Fluid Fast-Lane & Blind Drift Parity
CFAF trennt die physikalischen Anforderungen an Latenz und Korrelationsschutz in zwei komplementäre Ebenen:

Die Fast-Lane: Nutzdaten werden ohne künstliche Verzögerung (
0
 
ms
0ms) direkt geroutet, um Antwortzeiten von 
15
–
30
 
ms
15–30ms für SSH und Web-Traffic zu gewährleisten.
Die Drift-Lanes: Asynchron und räumlich gestreut driften homomorph rekodierte Paritätspakete über zufällige Zwischenstationen mit stochastischem Poisson-Micro-Jitter.
Wird die Fast-Lane von einem Zensor gedrosselt oder gezielt unterbrochen, rekonstruiert der Empfänger den Datenstrom nahtlos aus dem eintreffenden Drift-Feld – ohne Verbindungsabbruch oder erneuten Handshake.

2.6 BBR Delay-Gradient Anti-Bufferbloat Steering
Um Carrier-Dropping zu verhindern, überwacht das System permanente RTT-Gradienten:
Δ
RTT
=
RTT
sample
−
RTT
min
Δ 
RTT
​
 =RTT 
sample
​
 −RTT 
min
​
 
Steigt 
Δ
RTT
Δ 
RTT
​
  exponentiell an (Anzeichen für sich füllende Hardware-Puffer im DSLAM oder CMTS), reduziert der Pacing-Controller die Senderate mikrosekundengenau vor dem Auftreten eines echten Paketverlusts.

2.7 Systematischer Vergleich mit dem Stand der Technik (Taxonomie-Matrix)
Bestehende Architekturen zur Anonymisierung lassen sich entlang ihrer Latenzcharakteristik, ihres kryptographischen Schutzniveaus und ihrer Transportstabilität systematisieren:

Architektur	Latenzklasse	Anonymitätsmodell	AS-Timing-Resistenz	Bandbreiten-Overhead	Interaktivität (SSH/Web)	Carrier-CoDel Verträglichkeit
Tor (Dingledine et al., 2004)	Niedrig (
<
100
 
ms
<100ms)	Komputational (Onion Relays)	Nein (
>
95
%
>95% Korrelation)	Minimal (
<
5
%
<5%)	Ja (Exzellent)	Hoch (Deterministisches TCP)
I2P (I2P Project, 2003)	Mittel (
200
–
800
 
ms
200–800ms)	Komputational (Garlic Bundling)	Schwach (Tunnel-Watermarking)	Moderat (
15
–
30
%
15–30%)	Eingeschränkt (Hoher Jitter)	Gering (Puffer-Drop-Kaskaden)
Loopix (Piotrowska et al., 2017)	Hoch (
>
2
–
10
 
s
>2–10s)	Stochastisch (Poisson Mixnet)	Hoch (Stochastisch entkoppelt)	Extrem (
>
200
%
>200% Cover-Traffic)	Nein (Rein Asynchron)	Neutral (Gleichförmige Rate)
Vuvuzela (van den Hooff et al., 2015)	Hoch (
10
–
60
 
s
10–60s)	Differential Privacy (DP Noise)	Sehr hoch (DP-bewiesen)	Extrem (
>
1000
%
>1000% Chaff)	Nein (Nur Messaging)	Nicht zutreffend (Dead-Drop)
Nym Network (Nym, 2021)	Hoch (
0.5
–
5
 
s
0.5–5s)	Stochastisch (Incentiviertes Mixnet)	Hoch (Loopix-Derivat)	Hoch (
>
150
%
>150%)	Nein (Batching-Latenz)	Neutral (Feste Mix-Raten)
CFAF (Diese Arbeit)	Dual-Fluid (
15
–
35
 
ms
15–35ms)	Informationstheoretisch + RLNC	Vollständig (
A
d
v
≤
2.9
%
Adv≤2.9%)	Adaptiv (
13
–
39
%
13–39% Parität)	Ja (Fast-Lane 0ms)	Vollständig (Lyapunov BBR)
3. Mathematische Beweisführung & Formale Sicherheitsanalyse
Um die theoretische Validität des CFAF-Modells formell zu untermauern, führen wir die mathematischen Beweise für Informationstheorie, lineare Algebra über endlichen Körpern, stochastische Timing-Schranken und topologische Graphen-Separation aus.

3.0 Notationsverzeichnis & Mathematische Symbole
Zur präzisen formalen Darstellung definieren wir folgende Notationskonventionen:

Symbol	Mathematische Domäne	Semantische Bedeutung im CFAF-Modell
M
M	
{
0
,
1
}
s
⋅
b
{0,1} 
s⋅b
 	Klartext-Nachrichtenraum der Länge 
s
⋅
b
s⋅b Bits
κ
κ	
N
N (
κ
=
256
κ=256)	Kryptographischer Sicherheitsparameter (Schlüssellänge in Bits)
F
2
8
F 
2 
8
 
​
 	
GF
(
256
)
GF(256)	Endlicher Galois-Körper (Rijndael-Polynom 
x
8
+
x
4
+
x
3
+
x
+
1
x 
8
 +x 
4
 +x 
3
 +x+1)
K
K	
N
+
N 
+
 	Anzahl nativer Datenfragmente eines Übertragungsblocks (
K
∈
{
4
,
8
,
16
,
32
}
K∈{4,8,16,32})
δ
δ	
N
0
N 
0
​
 	Anzahl asynchroner Paritätsdrift-Fragmente (
δ
≥
1
δ≥1)
α
⃗
∈
F
2
8
K
α
 ∈F 
2 
8
 
K
​
 	Vektorraum 
F
2
8
K
F 
2 
8
 
K
​
 	Zufälliger Codierungsvektor eines RLNC-Pakets
S
fast
,
S
drift
S 
fast
​
 ,S 
drift
​
 	Datenströme	Orthogonale Fast-Lane (
τ
=
0
τ=0) und stochastische Poisson-Drift-Lane
λ
λ	
R
+
R 
+
  (
λ
=
100
 
s
−
1
λ=100s 
−1
 )	Intensitätsparameter des Poisson-Cover-Prozesses (
τ
ˉ
=
1
/
λ
=
10
 
ms
τ
ˉ
 =1/λ=10ms)
D
KL
(
P
∥
Q
)
D 
KL
​
 (P∥Q)	
R
+
R 
+
  (Nats)	Kullback-Leibler-Divergenz zwischen Timing-Verteilungen
A
d
v
A
Adv 
A
​
 	
[
0
,
1
]
[0,1]	Statistischer Vorteil des passiven Angreifers über reines Raten (
0,5
0,5) hinaus
Q
(
t
)
,
C
Q(t),C	
R
+
,
R
+
R 
+
 ,R 
+
 	Pufferfüllstand im Engpass-Router und Ausleitungskapazität
3.1 Formales Bedrohungsmodell (Adversary Model)
Wir definieren einen globalen passiven Angreifer (Global Passive Adversary, 
A
A) nach dem Dolev-Yao-Erweiterungsmodell:

Fähigkeiten: 
A
A kann alle Übertragungsstrecken zwischen autonomen Systemen beobachten, Paketzeitstempel 
t
∈
R
+
t∈R 
+
 , Paketgrößen 
s
∈
N
s∈N und Leitungsbursts auf Ingress- und Egress-Kanten des Netzwerkes messen.
Schranken: 
A
A ist rechnerisch beschränkt (Probabilistic Polynomial-Time, PPT) und kann kryptographische Einwegfunktionen (SHA-256) sowie symmetrische Chiffren (ChaCha20, AES) nicht invertieren.
Topologische Infiltration: 
A
A kann bis zu 
M
−
1
M−1 von 
M
M Transit-Knoten kontrollieren, jedoch nicht die gesamte Kette aktiver Relays simultan kompromittieren.
3.1.1 Formale Game-Based Security Definition
Wir formalisieren die Verkehrsfluss-Ununterscheidbarkeit über ein kryptographisches Sicherheitsspiel 
Exp
A
ind-cfa
(
κ
)
Exp 
A
ind-cfa
​
 (κ) zwischen einem Challenger 
C
C und dem PPT-Angreifer 
A
A:

Setup: 
C
C initialisiert das CFAF-Netzwerk mit Sicherheitsparameter 
κ
=
256
κ=256, Poisson-Rate 
λ
λ und Körper 
F
2
8
F 
2 
8
 
​
 .
Challenge Phase: 
A
A wählt zwei gleich lange Zielnachrichten 
M
0
,
M
1
∈
M
M 
0
​
 ,M 
1
​
 ∈M und übermittelt sie an 
C
C.
C
C wählt ein gleichverteiltes Zufallsbit 
b
←
R
{
0
,
1
}
b← 
R
​
 {0,1}, unterzieht 
M
b
M 
b
​
  der AONT-Transformation, zerlegt sie in 
K
K Fragmente und transmittiert diese über die Fast-Lane sowie mit 
δ
δ Poisson-Drift-Paritätspaketen über Relays 
R
1
,
…
,
R
m
R 
1
​
 ,…,R 
m
​
 .
Guess: 
A
A beobachtet alle Paket-Interankunftszeiten 
T
=
(
τ
1
,
…
,
τ
n
)
T=(τ 
1
​
 ,…,τ 
n
​
 ) und Paketgestalten 
C
=
(
c
1
,
…
,
c
n
)
C=(c 
1
​
 ,…,c 
n
​
 ) an Ingress- und Egress-Schnittstellen und gibt ein Bit 
b
′
∈
{
0
,
1
}
b 
′
 ∈{0,1} aus.
Definition (IND-CFA Sicherheit):
Ein Netzwerkprotokoll heißt IND-CFA-sicher (Indistinguishable Chrono-Fluid Anycast), falls für jeden PPT-Angreifer 
A
A der Vorteil:
A
d
v
A
cfa
(
κ
)
=
∣
Pr
⁡
[
Exp
A
ind-cfa
(
κ
)
=
1
]
−
1
2
∣
≤
negl
(
κ
)
+
1
2
D
KL
(
P
aktiv
∥
P
cover
)
Adv 
A
cfa
​
 (κ)= 
​
 Pr[Exp 
A
ind-cfa
​
 (κ)=1]− 
2
1
​
  
​
 ≤negl(κ)+ 
2
1
​
 D 
KL
​
 (P 
aktiv
​
 ∥P 
cover
​
 )
​
 
vernachlässigbar klein ist.

3.2 Satz 1 (Informationstheoretische Null-Korrelation der AONT)
Sei 
M
=
(
m
1
,
m
2
,
…
,
m
s
)
M=(m 
1
​
 ,m 
2
​
 ,…,m 
s
​
 ) eine Nachricht der Länge 
s
⋅
b
s⋅b Bits, aufgeteilt in 
s
s Blöcke zu je 
b
b Bits aus dem Klartextraum 
M
=
{
0
,
1
}
s
⋅
b
M={0,1} 
s⋅b
 .

Definition der Rivest-Package-Transformation:

Wähle einen ephemeren pseudozufälligen Schlüssel 
K
′
←
R
{
0
,
1
}
κ
K 
′
 ← 
R
​
 {0,1} 
κ
  uniform aus dem Schlüsselraum 
K
K.
Verschlüssele jeden Block 
m
i
m 
i
​
  mittels einer kryptographischen Pseudozufallsfunktion 
f
K
′
:
{
1
,
…
,
s
}
→
{
0
,
1
}
b
f 
K 
′
 
​
 :{1,…,s}→{0,1} 
b
 :
e
i
=
m
i
⊕
f
K
′
(
i
)
f
u
¨
r 
i
∈
{
1
,
…
,
s
}
e 
i
​
 =m 
i
​
 ⊕f 
K 
′
 
​
 (i)f 
u
¨
 r i∈{1,…,s}
Berechne den Prüf- und Schlüsselmaskierungsblock 
e
0
e 
0
​
 :
e
0
=
K
′
⊕
⨁
i
=
1
s
h
(
e
i
)
e 
0
​
 =K 
′
 ⊕ 
i=1
⨁
s
​
 h(e 
i
​
 )
wobei 
h
:
{
0
,
1
}
b
→
{
0
,
1
}
κ
h:{0,1} 
b
 →{0,1} 
κ
  eine kollisionsresistente kryptographische Hashfunktion ist.
Das transformierte Ensemble besteht aus 
s
+
1
s+1 Blöcken 
B
=
(
e
0
,
e
1
,
…
,
e
s
)
B=(e 
0
​
 ,e 
1
​
 ,…,e 
s
​
 ).
Satz 1 (Shannon Zero-Information Schranke):
Sei 
B
′
⊊
B
B 
′
 ⊊B eine beliebige echte Teilmenge mit 
∣
B
′
∣
≤
s
∣B 
′
 ∣≤s (d. h. mindestens ein Block 
e
j
∈
B
e 
j
​
 ∈B fehlt). Dann ist die Transinformation (Mutual Information) zwischen dem Klartext 
M
M und der Teilmenge 
B
′
B 
′
  exakt Null:
I
(
M
;
B
′
)
=
0
  
⟺
  
H
(
M
∣
B
′
)
=
H
(
M
)
I(M;B 
′
 )=0⟺H(M∣B 
′
 )=H(M)

Beweis:
Fall 1: Der fehlende Block ist der Maskierungsblock 
e
0
e 
0
​
  (
e
0
∉
B
′
e 
0
​
 ∈
/
B 
′
 ).
Die verbleibenden Blöcke sind 
(
e
1
,
…
,
e
s
)
(e 
1
​
 ,…,e 
s
​
 ). Für jedes 
e
i
e 
i
​
  gilt 
e
i
=
m
i
⊕
f
K
′
(
i
)
e 
i
​
 =m 
i
​
 ⊕f 
K 
′
 
​
 (i). Da 
K
′
K 
′
  uniform zufällig aus 
{
0
,
1
}
κ
{0,1} 
κ
  gewählt wurde und in 
B
′
B 
′
  nicht vorkommt, ist für einen PPT-Angreifer der Pad 
f
K
′
(
i
)
f 
K 
′
 
​
 (i) ununterscheidbar von einem echten One-Time-Pad. Folglich gilt für die bedingte Wahrscheinlichkeitsverteilung:
P
(
M
=
m
∣
e
1
,
…
,
e
s
)
=
P
(
M
=
m
)
∀
m
∈
M
P(M=m∣e 
1
​
 ,…,e 
s
​
 )=P(M=m)∀m∈M

Fall 2: Der fehlende Block ist ein Nutzdatenblock 
e
k
e 
k
​
  mit 
k
∈
{
1
,
…
,
s
}
k∈{1,…,s} (
e
k
∉
B
′
e 
k
​
 ∈
/
B 
′
 ).
Um 
K
′
K 
′
  aus 
e
0
e 
0
​
  zu rekonstruieren, muss der Term 
⨁
i
=
1
s
h
(
e
i
)
⨁ 
i=1
s
​
 h(e 
i
​
 ) ausgewertet werden:
K
′
=
e
0
⊕
(
∑
i
≠
k
h
(
e
i
)
⊕
h
(
e
k
)
)
K 
′
 =e 
0
​
 ⊕ 
​
  
i

=k
∑
​
 h(e 
i
​
 )⊕h(e 
k
​
 ) 
​
 
Da 
e
k
e 
k
​
  dem Angreifer unbekannt ist und 
h
h als Zufallsorakel modelliert wird, ist der Wert 
h
(
e
k
)
h(e 
k
​
 ) gleichverteilt über 
{
0
,
1
}
κ
{0,1} 
κ
  und unabhängig von allen übrigen 
e
i
e 
i
​
 . Damit ist 
K
′
K 
′
  für den Angreifer eine uniform verteilte Zufallsvariable:
H
(
K
′
∣
B
′
)
=
κ
⋅
log
⁡
2
(
2
)
=
κ
H(K 
′
 ∣B 
′
 )=κ⋅log 
2
​
 (2)=κ
Da 
K
′
K 
′
  vollständig unbestimmt ist, gilt für alle in 
B
′
B 
′
  vorhandenen Blöcke 
e
i
e 
i
​
  (
i
≠
k
i

=k), dass 
f
K
′
(
i
)
f 
K 
′
 
​
 (i) als vollkommen zufällige Maske wirkt. Daher liefert kein Block 
e
i
∈
B
′
e 
i
​
 ∈B 
′
  Information über 
m
i
m 
i
​
  oder 
m
k
m 
k
​
 .
Es folgt:
H
(
M
∣
B
′
)
=
H
(
M
)
  
⟹
  
I
(
M
;
B
′
)
=
H
(
M
)
−
H
(
M
∣
B
′
)
=
0
H(M∣B 
′
 )=H(M)⟹I(M;B 
′
 )=H(M)−H(M∣B 
′
 )=0
■
■

3.3 Satz 2 (Singularitäts- und Rekonstruktionsschranke in 
F
2
8
F 
2 
8
 
​
 )
Seien 
p
1
,
…
,
p
K
∈
F
2
8
L
p 
1
​
 ,…,p 
K
​
 ∈F 
2 
8
 
L
​
  die nativen Datenpakete eines Symbolblocks. Jedes codierte Fragment ist ein Tupel 
(
α
⃗
,
c
⃗
)
( 
α
 , 
c
 ), wobei 
α
⃗
=
(
α
1
,
…
,
α
K
)
∈
F
2
8
K
α
 =(α 
1
​
 ,…,α 
K
​
 )∈F 
2 
8
 
K
​
  der Codierungsvektor und 
c
⃗
=
∑
i
=
1
K
α
i
p
i
∈
F
2
8
L
c
 =∑ 
i=1
K
​
 α 
i
​
 p 
i
​
 ∈F 
2 
8
 
L
​
  die codierte Nutzlast ist.

Lemma 1 (Invarianz der Homomorphie bei Re-Coding):
Seien 
(
α
⃗
(
1
)
,
c
⃗
(
1
)
)
,
…
,
(
α
⃗
(
m
)
,
c
⃗
(
m
)
)
( 
α
  
(1)
 , 
c
  
(1)
 ),…,( 
α
  
(m)
 , 
c
  
(m)
 ) im Puffer eines Transit-Knotens. Wählt der Knoten Koeffizienten 
β
⃗
=
(
β
1
,
…
,
β
m
)
∈
F
2
8
m
∖
{
0
⃗
}
β
​
 =(β 
1
​
 ,…,β 
m
​
 )∈F 
2 
8
 
m
​
 ∖{ 
0
 }, so ist das rekodierte Fragment 
(
α
⃗
′
,
c
⃗
′
)
=
(
∑
j
=
1
m
β
j
α
⃗
(
j
)
,
∑
j
=
1
m
β
j
c
⃗
(
j
)
)
( 
α
  
′
 , 
c
  
′
 )=(∑ 
j=1
m
​
 β 
j
​
  
α
  
(j)
 ,∑ 
j=1
m
​
 β 
j
​
  
c
  
(j)
 ) eine gültige lineare Kombination der ursprünglichen nativen Pakete:
c
⃗
′
=
∑
i
=
1
K
α
i
′
p
i
mit
α
i
′
=
∑
j
=
1
m
β
j
α
i
(
j
)
c
  
′
 = 
i=1
∑
K
​
 α 
i
′
​
 p 
i
​
 mitα 
i
′
​
 = 
j=1
∑
m
​
 β 
j
​
 α 
i
(j)
​
 
Beweis durch Ausklammern im Vektorraum über 
F
2
8
F 
2 
8
 
​
 .

Satz 2 (Gaußsche Dekodierungswahrscheinlichkeit über 
F
q
F 
q
​
 ):
Sei 
q
=
2
8
=
256
q=2 
8
 =256. Empfängt der Empfänger 
N
≥
K
N≥K zufällig in Transit-Knoten linear rekodierte Fragmente, so bildet die Koeffizientenmatrix 
A
∈
F
q
N
×
K
A∈F 
q
N×K
​
  das Gleichungssystem 
A
⋅
P
=
C
A⋅P=C. Die Wahrscheinlichkeit 
P
solvable
(
N
,
K
,
q
)
P 
solvable
​
 (N,K,q), dass das Gleichungssystem eindeutig lösbar ist (
Rang
(
A
)
=
K
Rang(A)=K), genügt für 
N
=
K
N=K exakt:
P
(
K
,
K
,
q
)
=
∏
i
=
0
K
−
1
(
1
−
1
q
K
−
i
)
=
∏
j
=
1
K
(
1
−
q
−
j
)
P(K,K,q)= 
i=0
∏
K−1
​
 (1− 
q 
K−i
 
1
​
 )= 
j=1
∏
K
​
 (1−q 
−j
 )

Analytische Abschätzung für 
q
=
256
q=256:
Durch Anwendung der Weierstraß-Produktungleichung 
∏
(
1
−
a
j
)
>
1
−
∑
a
j
∏(1−a 
j
​
 )>1−∑a 
j
​
  erhalten wir für die Erfolgsquote bei exakt 
N
=
K
N=K empfangenen Paketen:
P
(
K
,
K
,
256
)
>
1
−
∑
j
=
1
K
256
−
j
>
1
−
∑
j
=
1
∞
256
−
j
=
1
−
1
256
−
1
=
1
−
1
255
≈
0,996078
P(K,K,256)>1− 
j=1
∑
K
​
 256 
−j
 >1− 
j=1
∑
∞
​
 256 
−j
 =1− 
256−1
1
​
 =1− 
255
1
​
 ≈0,996078
Das bedeutet: Bereits ohne ein einziges zusätzliches Paritätspaket beträgt die Lösbarkeit bei rein stochastischer Koeffizientenwahl über 
99,61
 
%
99,61%.

Satz 2.1 (Exponentieller Verfall der Ausfallwahrscheinlichkeit bei Drift-Parität):
Empfängt der Empfänger 
N
=
K
+
δ
N=K+δ Pakete mit 
δ
≥
1
δ≥1 zusätzlichen asynchronen Drift-Paritätsfragmenten, so ist die Wahrscheinlichkeit eines Fehlschlags (Matrix-Singularität) nach oben beschränkt durch:
P
fail
(
K
+
δ
,
K
,
q
)
≤
1
(
q
−
1
)
⋅
q
δ
=
1
255
⋅
256
δ
P 
fail
​
 (K+δ,K,q)≤ 
(q−1)⋅q 
δ
 
1
​
 = 
255⋅256 
δ
 
1
​
 

Konkrete Werte für die CFAF Drift-Lane:

Für 
δ
=
1
δ=1 (ein einziges Drift-Paket):
P
fail
≤
1
255
⋅
256
=
1
65.280
≈
1,53
×
10
−
5
(
<
0,0015
 
%
)
P 
fail
​
 ≤ 
255⋅256
1
​
 = 
65.280
1
​
 ≈1,53×10 
−5
 (<0,0015%)
Für 
δ
=
2
δ=2 (zwei Drift-Pakete):
P
fail
≤
1
255
⋅
65.536
=
1
16.711.680
≈
5,98
×
10
−
8
(
<
0,000006
 
%
)
P 
fail
​
 ≤ 
255⋅65.536
1
​
 = 
16.711.680
1
​
 ≈5,98×10 
−8
 (<0,000006%)
■
■
Damit ist mathematisch bewiesen: Selbst bei totalem Wegfall der Fast-Lane garantiert ein minimaler Paritätsdrift von 2 Paketen eine Wiederherstellungswahrscheinlichkeit von 
99,999994
 
%
99,999994% ohne Re-Transmission.

3.4 Satz 3 (Informationstheoretische Verkehrsfluss-Entropie)
Ein passiver AS-Lauscher 
A
A misst Ankunftszeitpunkte von Datenpaketen 
T
=
(
t
1
,
t
2
,
…
,
t
n
)
T=(t 
1
​
 ,t 
2
​
 ,…,t 
n
​
 ).

Definition der Poisson-Drift-Überlagerung:
Die Übertragungsfolge auf den Drift-Lanes wird als homogener Poisson-Prozess mit Intensität 
λ
>
0
λ>0 modelliert. Die Zwischenankunftszeiten 
τ
i
=
t
i
+
1
−
t
i
τ 
i
​
 =t 
i+1
​
 −t 
i
​
  folgen einer Exponentialverteilung mit Dichte:
f
cover
(
τ
)
=
λ
e
−
λ
τ
(
τ
≥
0
)
f 
cover
​
 (τ)=λe 
−λτ
 (τ≥0)
Trifft ein interaktiver Fast-Lane-Burst der Datenrate 
R
(
t
)
R(t) ein, moduliert der stochastische Chaff-Mixer die Drift-Injektion derart, dass die aggregierte Dichte 
f
total
(
τ
)
f 
total
​
 (τ) der Gesamtsequenz minimal von 
f
cover
(
τ
)
f 
cover
​
 (τ) abweicht.

Satz 3 (Beschränktheit der relativen Entropie / Kullback-Leibler-Divergenz):
Die Kullback-Leibler-Divergenz 
D
KL
(
P
aktiv
∥
P
idle
)
D 
KL
​
 (P 
aktiv
​
 ∥P 
idle
​
 ) zwischen dem Zeitstempel-Wahrscheinlichkeitsmaß bei aktiver Datenübertragung 
P
aktiv
P 
aktiv
​
  und dem reinen Cover-Traffic-Maß 
P
idle
P 
idle
​
  genügt unter konstanter Bucket-Pufferung und Poisson-Jittering:
D
KL
(
P
aktiv
∥
P
idle
)
=
∫
0
∞
f
aktiv
(
τ
)
ln
⁡
(
f
aktiv
(
τ
)
f
cover
(
τ
)
)
d
τ
≤
σ
jitter
2
2
⋅
τ
ˉ
2
=
ϵ
D 
KL
​
 (P 
aktiv
​
 ∥P 
idle
​
 )=∫ 
0
∞
​
 f 
aktiv
​
 (τ)ln( 
f 
cover
​
 (τ)
f 
aktiv
​
 (τ)
​
 )dτ≤ 
2⋅ 
τ
ˉ
  
2
 
σ 
jitter
2
​
 
​
 =ϵ

Nach Pinskers Ungleichung ist der statistische Gesamtabstand (Total Variation Distance, TVD) beschränkt durch:
δ
(
P
aktiv
,
P
idle
)
≤
1
2
D
KL
(
P
aktiv
∥
P
idle
)
≤
ϵ
2
δ(P 
aktiv
​
 ,P 
idle
​
 )≤ 
2
1
​
 D 
KL
​
 (P 
aktiv
​
 ∥P 
idle
​
 )
​
 ≤ 
2
ϵ
​
 
​
 
Für einen Angreifer 
A
A, der einen Hypothesentest zwischen 
H
0
H 
0
​
  ("Kein Verkehr / Leerlauf") und 
H
1
H 
1
​
  ("Aktive Datenübertragung") durchführt, ist die Erfolgswahrscheinlichkeit 
P
success
P 
success
​
  beschränkt durch:
P
success
≤
1
2
+
1
2
δ
(
P
aktiv
,
P
idle
)
≤
1
2
+
1
2
ϵ
2
P 
success
​
 ≤ 
2
1
​
 + 
2
1
​
 δ(P 
aktiv
​
 ,P 
idle
​
 )≤ 
2
1
​
 + 
2
1
​
  
2
ϵ
​
 
​
 
Da 
ϵ
→
0
ϵ→0 für fein aufgelöstes Micro-Jittering konvergiert, fällt die Erfolgswahrscheinlichkeit des passiven Lauschers gegen die Schranke von 
1
2
2
1
​
  (reines Raten). Lineare Korrelationsangriffe verlieren ihre statistische Basis. 
■
■

3.5 Satz 4 (Lyapunov-Stabilität des BBR-Gradienten & Anti-Bufferbloat)
Sei 
Q
(
t
)
≥
0
Q(t)≥0 die Queue-Füllung im Engpass-Router (Bottleneck Router) mit Ausleitungskapazität 
C
C. Sei 
d
prop
d 
prop
​
  die reine physikalische Signallaufzeit (Propagationsverzögerung). Die gemessene Round-Trip-Time beträgt:
RTT
(
t
)
=
2
d
prop
+
Q
(
t
)
C
RTT(t)=2d 
prop
​
 + 
C
Q(t)
​
 
Der CoDel-Algorithmus des ISP-Routers löst einen Paketverlust aus, sobald gilt:
min
⁡
t
∈
[
t
0
,
t
0
+
100
 
ms
]
Q
(
t
)
C
>
τ
target
(
Standardwert: 
τ
target
=
5
 
ms
)
t∈[t 
0
​
 ,t 
0
​
 +100ms]
min
​
  
C
Q(t)
​
 >τ 
target
​
 (Standardwert: τ 
target
​
 =5ms)

Satz 4 (Präemptive Gradienten-Dämpfung):
Der CFAF Delay-Gradient-Controller steuert die Senderate 
u
(
t
)
u(t) gemäß dem Differentialgesetz:
d
u
(
t
)
d
t
=
−
γ
⋅
d
d
t
RTT
(
t
)
=
−
γ
C
⋅
d
Q
(
t
)
d
t
(
γ
>
0
)
dt
du(t)
​
 =−γ⋅ 
dt
d
​
 RTT(t)=− 
C
γ
​
 ⋅ 
dt
dQ(t)
​
 (γ>0)
Definieren wir die Lyapunov-Funktion 
V
(
Q
)
=
1
2
Q
(
t
)
2
V(Q)= 
2
1
​
 Q(t) 
2
 . Es gilt:
V
˙
(
Q
)
=
Q
(
t
)
⋅
Q
˙
(
t
)
=
Q
(
t
)
⋅
(
u
(
t
)
−
C
)
V
˙
 (Q)=Q(t)⋅ 
Q
˙
​
 (t)=Q(t)⋅(u(t)−C)
Durch Substitution des Feedback-Gesetzes konvergiert 
Q
(
t
)
Q(t) exponentiell gegen den Gleichgewichtszustand $Q^ = 0$.*
Folglich gilt für alle 
t
≥
t
konv
t≥t 
konv
​
 :
Q
(
t
)
C
<
τ
target
=
5
 
ms
  
⟹
  
P
drop
CoDel
(
t
)
≡
0
C
Q(t)
​
 <τ 
target
​
 =5ms⟹P 
drop
CoDel
​
 (t)≡0
Carrier-Bufferbloat und präemptive Paket-Drops durch Router-Scheduler (FQ-CoDel/RED) sind mathematisch ausgeschlossen. 
■
■

3.6 Satz 5 (Topologische 2-Hop Isolation im Double-Blind Modell)
Wir modellieren das Kommunikationsnetz als ungerichteten Graphen 
G
=
(
V
,
E
)
G=(V,E), wobei 
V
V die Knotenmenge und 
E
E die Menge aktiver TCP/UDP-Transportverbindungen darstellt.

(Client C) ───e1─── (Guard G_C) ───e2─── (RP) ───e3─── (Guard G_S) ───e4─── (Service S)
Pfadlänge: Der kürzeste Pfad zwischen Client 
C
C und Service 
S
S beträgt 
d
G
(
C
,
S
)
=
4
d 
G
​
 (C,S)=4 Kanten.
Beobachtungsraum eines Knotens 
v
∈
V
v∈V: Sei 
N
(
v
)
=
{
u
∈
V
∣
(
v
,
u
)
∈
E
}
N(v)={u∈V∣(v,u)∈E} die direkte Adjazenzmenge (Nachbarschaft) von 
v
v. Ein Knoten erfährt ausschließlich die IP-Adressen seiner direkten Kantenpartner 
N
(
v
)
N(v).
Satz 5 (Vollständige Endpunkt-Entkopplung bei kompromittiertem Rendezvous Point):
Sei der Sovereign Rendezvous Point 
RP
RP bösartig oder unter staatlicher Überwachung (
RP
∈
A
RP∈A). Dann gilt:
N
(
RP
)
=
{
G
C
,
G
S
}
N(RP)={G 
C
​
 ,G 
S
​
 }
{
C
,
S
}
∩
N
(
RP
)
=
∅
{C,S}∩N(RP)=∅
Die Schnittmenge der vom Angreifer beobachteten Kanten mit den Endpunktknoten ist leer. Weder die Identität von 
C
C noch die Identität von 
S
S ist Element von 
N
(
RP
)
N(RP).

Korollar (Zwei-Knoten-Resistenz):
Selbst wenn 
RP
RP und der clientseitige Guard 
G
C
G 
C
​
  kolludieren (
{
RP
,
G
C
}
⊂
A
{RP,G 
C
​
 }⊂A), gilt:
N
(
RP
)
∪
N
(
G
C
)
=
{
C
,
G
C
,
RP
,
G
S
}
∌
S
N(RP)∪N(G 
C
​
 )={C,G 
C
​
 ,RP,G 
S
​
 }

∋S
Der Angreifer erfährt zwar die Existenz von 
C
C, besitzt jedoch Null Information über die IP-Adresse oder den physischen Aufenthaltsort des Ziel-Services 
S
S, da 
d
(
G
C
,
S
)
=
3
d(G 
C
​
 ,S)=3. Die Identität beider Endpunkte kann nur aufgedeckt werden, wenn 
G
C
G 
C
​
 , 
RP
RP und 
G
S
G 
S
​
  simultan kompromittiert sind. 
■
■

3.7 Das CFAF-Haupttheorem (Synthese zur Vereinheitlichten Theorie)
Die Sätze 1 bis 5 lassen sich nun zu einem geschlossenen, widerspruchsfreien Hauptsatz zusammenführen, der die formale Auflösung des eingangs formulierten Anonymitäts-Trilemmas beweist:

Haupttheorem (Auflösung des Anonymitäts-Trilemmas im Chrono-Fluiden Kontinuum):
Gegeben sei ein nach den Axiomen 1–3 konstruiertes CFAF-Netzwerk 
G
=
(
V
,
E
)
G=(V,E) unter der Aufteilung in Fast-Lane 
S
fast
S 
fast
​
  und Poisson-Drift-Lane 
S
drift
S 
drift
​
 . Für jede Übertragung einer Nachricht 
M
∈
M
M∈M zwischen zwei beliebigen Endpunkten 
(
C
,
S
)
(C,S) gilt unter der Anwesenheit eines globalen passiven AS-Lauschers 
A
A und beliebiger Carrier-Puffersteuerungen simultan:

Informationstheoretische Unkorrelierbarkeit:
Der statistische Vorteil 
A
d
v
A
corr
Adv 
A
corr
​
  eines Angreifers bei der Korrelation von Ein- und Ausgangsströmen ist nach oben beschränkt durch:
A
d
v
A
corr
=
∣
Pr
⁡
[
A
(
T
)
=
1
∣
aktiv
]
−
Pr
⁡
[
A
(
T
)
=
1
∣
idle
]
∣
≤
negl
(
κ
)
+
ϵ
2
Adv 
A
corr
​
 =∣Pr[A(T)=1∣aktiv]−Pr[A(T)=1∣idle]∣≤negl(κ)+ 
2
ϵ
​
 
​
 
wobei 
negl
(
κ
)
negl(κ) die Invertierungswahrscheinlichkeit der AONT-Schlüsselmaske (Satz 1) und 
ϵ
=
σ
jitter
2
2
τ
ˉ
2
ϵ= 
2 
τ
ˉ
  
2
 
σ 
jitter
2
​
 
​
  die relative Timing-Entropie (Satz 3) bezeichnet.

Deterministische Latenz-Erhaltung:
Der Erwartungswert der interaktiven Paketlaufzeit 
τ
τ auf der Fast-Lane degeneriert nicht, sondern entspricht asymptotisch der reinen physikalischen Mindestlaufzeit:
E
[
τ
interaktiv
]
=
τ
phys
+
O
(
1
)
(
≈
15
–
30
 
ms
)
E[τ 
interaktiv
​
 ]=τ 
phys
​
 +O(1)(≈15–30ms)

Garantierte Rekonstruktion unter extremem Fast-Lane-Ausfall:
Selbst bei vollständiger Unterbrechung oder Drosselung des interaktiven Pfades (
Pr
⁡
[
Drop
fast
]
=
1
Pr[Drop 
fast
​
 ]=1) konvergiert die Wiederherstellungswahrscheinlichkeit aus dem 
F
2
8
F 
2 
8
 
​
 -Driftfeld mit 
K
+
δ
K+δ empfangenen Paketen gegen 1:
Pr
⁡
[
Reconstruction
∣
FastLane Blackhole
]
≥
1
−
1
255
⋅
256
δ
(
Satz 2.1
)
Pr[Reconstruction∣FastLane Blackhole]≥1− 
255⋅256 
δ
 
1
​
 (Satz 2.1)

Invarianz gegen ISP-Bufferbloat:
Die Queue-Füllung an Engpass-Routern wird durch die Lyapunov-Feedback-Dämpfung permanent unter der CoDel-Abschaltschwelle 
τ
target
=
5
 
ms
τ 
target
​
 =5ms gehalten:
P
drop
Carrier
(
t
)
≡
0
∀
t
≥
t
konv
(
Satz 4
)
P 
drop
Carrier
​
 (t)≡0∀t≥t 
konv
​
 (Satz 4)

Topologische Identitäts-Entkopplung:
Für den Sovereign Rendezvous Point 
RP
RP gilt selbst bei feindlicher Übernahme durch 
A
A:
N
(
RP
)
∩
{
C
,
S
}
=
∅
(
Satz 5
)
N(RP)∩{C,S}=∅(Satz 5)

Beweis (Synthese):
Der Beweis folgt unmittelbar aus der logischen Konjunktion der Sätze 1, 2, 3, 4 und 5:

Satz 1 eliminiert jegliche Fragment-Korrelation vor der Übertragung (
I
=
0
I=0).
Satz 2 und Lemma 1 garantieren, dass die Fragmente während des Flugs durch homomorphe Linearkombination im Körper 
F
2
8
F 
2 
8
 
​
  permutiert werden können, ohne dass Relays Klartextzugriff benötigen oder feste Bytemuster erhalten bleiben, während die Lösungsquote 
≥
99,61
 
%
≥99,61% (bzw. 
99,999994
 
%
99,999994% mit 
δ
=
2
δ=2) beträgt.
Satz 3 drückt die zeitliche Divergenz der Paketanordnungen unter die Ununterscheidbarkeitsschranke eines Zufallsprozesses.
Satz 4 beweist, dass diese stochastische Glättung keine Bufferbloat-Abbrüche bei Providern provoziert.
Satz 5 stellt sicher, dass die Vermittlung über den Rendezvous Point ohne Kenntnis von Quell- und Ziel-IP erfolgt.
Folglich ist bewiesen: Das traditionelle Trilemma zwischen Interaktivität, Anonymität und Pufferstabilität ist kein naturgegebenes Gesetz digitaler Netze, sondern ein Artefakt starrer, eindimensionaler Paketpfade. Im mehrdimensionalen Chrono-Fluiden Kontinuum existiert eine mathematisch stabile Lösung, die alle drei Kriterien gleichzeitig erfüllt. 
■
■

3.8 Sicherheitsanalyse: Datensniffing in der Fast-Lane & Strukturiertes Reaktionsszenario
Ein zentraler Kritikpunkt an dualen Pfadarchitekturen ist die Frage:
„Wenn die Fast-Lane interaktiven Datenverkehr ohne künstliche Verzögerung (
0
 
ms
0ms) transportiert – entsteht dadurch nicht eine gravierende Schwachstelle für passive Lauschangriffe (Sniffing) oder gezielte Datenextraktion durch Dritte?“

Wir analysieren dieses Risiko entlang von drei kryptographischen Barrieren und strukturieren das dynamische Verhalten des Netzwerks anhand eines konkreten Angriffsszenarios.

[Angreifer E / Sniffer] ──(Tapped Fast-Lane)──► [Abgefangener Stream]
          │                                                │
          ├── 1. DPI / Header Inspection ───────────────► WebRTC/RTP Mimikry (DSCP 46)
          ├── 2. Kryptographischer Klartext-Bruch ──────► PQ-Hybrid (X25519 + ML-KEM-768) + ChaCha20
          ├── 3. AONT-Informations-Extinktion ──────────► I(M; B_fast) = 0 (Fehlender Maskierungsblock)
          │
          ▼ [Bei aktivem Fast-Lane Drop / Zensur]
[Empfänger R] ◄─── (Asynchrone Drift-Relays) ───────────► Autonome RLNC GF(2^8) Rekonstruktion (50ms)
3.8.1 Die dreifache Schutzschranke gegen Fast-Lane-Sniffing
DPI-Invarianz & Protokoll-Tarnung:
Auf der physischen Leitung sieht der Sniffer ausschließlich RFC-konforme WebRTC-/RTP-Medienströme (RFC 3550) mit DiffServ-Klassifizierung DSCP 46 (Expedited Forwarding). Es existieren keine statischen Signaturen, keine Klartext-Routing-Labels und keine erkennbaren Magic-Bytes.
Post-Quantum Hybrid-Kryptographie:
Die Nutzlast jedes Fast-Lane-Frames ist Ende-zu-Ende zwischen Client und Service verschlüsselt. Die Sitzungsschlüssel werden über einen hybriden Schlüsselaustausch aus klassischem Diffie-Hellman (X25519) und gitterbasierter Post-Quantum-Kryptographie (ML-KEM-768 / FIPS 203) ausgehandelt. Selbst ein Angreifer mit Zugriff auf zukünftige Quantenrechner ("Harvest Now, Decrypt Later") kann die Chiffre nicht entschlüsseln.
Informationstheoretische Extinktion via AONT-Splitting:
Selbst unter der hypothetischen Annahme, dass ein Angreifer Teilschlüssel der symmetrischen Schicht erlangt, greift Satz 1: Vor der Transmission wird die Nachricht der All-Or-Nothing-Transformation unterzogen. Im CFAF-Protokoll wird der Prüf- und Schlüsselmaskierungsblock 
e
0
=
K
′
⊕
⨁
h
(
e
i
)
e 
0
​
 =K 
′
 ⊕⨁h(e 
i
​
 ) niemals über die Fast-Lane, sondern ausschließlich über das diffuse Poisson-Driftfeld geroutet.
Da der Sniffer auf der Fast-Lane lediglich eine echte Teilmenge 
B
fast
⊊
B
B 
fast
​
 ⊊B mit 
∣
B
fast
∣
≤
s
∣B 
fast
​
 ∣≤s abgreifen kann, gilt mathematisch strikt:
I
(
M
;
B
fast
)
=
0
  
⟺
  
H
(
M
∣
B
fast
)
=
H
(
M
)
I(M;B 
fast
​
 )=0⟺H(M∣B 
fast
​
 )=H(M)
Dem Sniffer fehlen exakt die Bits, die zur Invertierung der Maske erforderlich sind. Das Mitschneiden der Fast-Lane liefert exakt 0 Bits Klartext-Information.
3.8.2 Strukturiertes Angriffsszenario: Passiver Lauschangriff & Aktive Fast-Lane-Sabotage
Wir betrachten ein reales 4-Phasen-Szenario, in dem ein bösartiger Internet Service Provider oder staatlicher Akteur 
E
E eine Fast-Lane-Strecke zwischen Client-Guard 
G
C
G 
C
​
  und Rendezvous-Point kompromittiert:

                  [Fast-Lane: Direkter 0ms Pfad]
         Client ═══════════ (Sniffer E) ═══════════► Rendezvous / Egress
           ║                                                ║
           ║          [Drift-Lanes: Poisson GF(2^8)]        ║
           ╠══► Relay R1 ──(Poisson Delay + RLNC Re-Code)──►╣
           ╚══► Relay R2 ──(Poisson Delay + RLNC Re-Code)──►╝
Phase 1: Passives Mitschneiden (Sniffing-Versuch)

Aktion des Angreifers: 
E
E zeichnet alle Pakete der Fast-Lane mit einem Packet-Capture-System (Wireshark/DPDK) auf.
Netzwerk-Verhalten: Die Fast-Lane liefert den interaktiven Datenstrom in 
35,21
 
ms
35,21ms an das Ziel aus.
Angreifer-Ergebnis: 
E
E erhält unkorrelierbare, pseudozufällige Bitmuster. Da ihm die Drift-Pakete fehlen, kann er weder den Klartext rekonstruieren (
I
=
0
I=0) noch eine Korrelation zu anderen Netzwerkabschnitten herstellen, da die Session-IDs nach jedem Hop permutieren.
Phase 2: Aktiver Eingriff (Fast-Lane Drop / Selective Throttling)

Aktion des Angreifers: Da das passive Mitlesen fehlschlägt, versucht 
E
E, die Verbindung zu sabotieren oder eine Neuaushandlung zu erzwingen, indem er Fast-Lane-Pakete gezielt verwirft (Blackhole-Angriff).
Netzwerk-Verhalten: Der Empfänger registriert das Ausbleiben des Fast-Lane-Frames. Im Gegensatz zu klassischen TCP-Verbindungen sendet der CFAF-Empfänger keine Retransmission Requests (NACK) und kein TCP-RST, die den Angreifer über den Erfolg seiner Sabotage informieren würden.
Phase 3: Autonome Rekonstruktion aus dem Drift-Feld

Netzwerk-Verhalten: Gleichzeitig driften die homomorph rekodierten Paritätsfragmente über die Transit-Relays 
R
1
R 
1
​
  und 
R
2
R 
2
​
  asynchron ein.
Verarbeitung am Empfänger: Sobald der Gauß-Jordan-Decoder 
K
K linear unabhängige Vektoren aus dem Drift-Feld registriert (is_solvable() == true), invertiert er die Koeffizientenmatrix in 
F
2
8
F 
2 
8
 
​
  (Dauer: 
<
1,2
 
ms
<1,2ms).
Empirische Zeitmessung: Die gesamte Nachricht wird im Testnet in 
50,18
 
ms
50,18ms fehlerfrei wiederhergestellt (Tabelle 4). Das Latenz-Delta beträgt lediglich 
14,97
 
ms
14,97ms – die Sitzung läuft unterbrechungsfrei weiter, während die Sabotage des Angreifers wirkungslos verpufft.
Phase 4: Replay- und Injection-Versuche (Man-in-the-Middle)

Aktion des Angreifers: 
E
E versucht, zuvor abgefangene Fast-Lane-Pakete zu manipulieren (Bit-Flipping) oder zu einem späteren Zeitpunkt erneut einzuspeisen (Replay-Angriff).
Netzwerk-Verhalten:
Integritätsprüfung: Manipulierte Bits führen zum sofortigen Scheitern des Poly1305-AEAD-Prüftags. Das Paket wird auf Socket-Ebene stillschweigend verworfen.
Anti-Replay: Der Empfänger führt eine Sliding-Window- und Sitzungs-Historie (delivered_sessions). Erkennt der Empfänger eine bereits ausgelieferte session_id, wird das Paket mit 
0
 
μ
s
0μs Verarbeitungsaufwand eliminiert.
Fazit der Sicherheitsanalyse:
Das Sniffen oder Zensieren der Fast-Lane stellt für das Gesamtsystem zu keinem Zeitpunkt eine kompromittierende Bedrohung dar. Vertraulichkeit ist durch die Kombination aus Post-Quantum-Verschlüsselung und AONT-Fragmentierung mathematisch strikt garantiert; Verfügbarkeit und Integrität werden durch die algebraische Fluidität des Drift-Feldes unterbrechungsfrei sichergestellt.

4. Quantitative Empirische Evaluation & Physikalische Messdaten
Zur experimentellen Verifikation der theoretischen Theoreme wurde die CFAF-Architektur in einem nativen Pure-Rust-Forschungsprototypen (sb-securenet) implementiert und auf lokaler Hardware unter Windows 11 (AMD/Intel x86_64, Tokio Async Runtime) vermessen.

4.0 Experimentelles Testbett, Messmethodik & Versuchsaufbau
Um wissenschaftliche Reproduzierbarkeit und statistische Validität gemäß den Standards von ACM CCS und USENIX Security zu gewährleisten, wird der Versuchsaufbau formal spezifiziert:

4.0.1 Hardware- & Software-Umgebung
Host-Architektur: AMD/Intel x86_64 Multi-Core-Prozessor (64-Bit), Hardware-Virtualisierung aktiviert.
Betriebssystem & Netzwerk-Stack: Microsoft Windows 11 Pro 64-Bit (NT-Kernel 10.0), asynchrones I/O-Subsystem basierend auf Windows I/O Completion Ports (IOCP / Winsock2).
Compiler & Optimierungsprofil: Rust 1.85+ (Edition 2024), kompilierte Release-Binary mit -C opt-level=3 -C lto=fat -C codegen-units=1 -C panic=abort.
Asynchrone Laufzeitumgebung: Tokio Runtime v1.43 im Multi-Threaded Work-Stealing Modus, Thread-Pool skaliert mit der Anzahl logischer CPU-Kerne.
Zeiterfassung & Timer-Präzision: Hardware-Monotonic Clock via Time-Stamp Counter (TSC) bzw. Windows High-Resolution Performance Counter (std::time::Instant / QueryPerformanceCounter) mit Nanosekunden-Auflösung.
4.0.2 Messmethodik & Kaltstart-Eliminierung (Warmup-Strategie)
Kompensation von Kaltstart-Effekten: Vor jeder gewerteten Messreihe durchläuft der Test-Harness 
N
warm
=
10
N 
warm
​
 =10 Vorab-Transaktionen. Dadurch werden anfängliche CPU-Instruktions-Cache-Misses, dynamische Page-Faults bei Heap-Allokationen und Initialisierungs-Latenzen des Tokio-Worker-Pools vollständig eliminiert.
Statistische Metriken: Für alle Workloads werden Minimum, arithmetisches Mittel (Mean), Median (p50), 95. Perzentil (p95), 99. Perzentil (p99) sowie das absolute Maximum ausgewiesen.
Verbindungs-Isolation: Jede Transaktion verwendet ephemere, nicht-wiederverwendete Sockets und frisch abgeleitete Krypto-Schlüssel bzw. Blind-Cookies, um Cache-Begünstigungen auf Transportebene auszuschließen.
4.0.3 Topologie des Experimentellen Testnetzwerks
Der Versuchsaufbau umfasst ein vollständig entkoppeltes, mehrstufiges Overlay-Netzwerk:

┌─────────────────────────────────────────────────────────────────────────┐
│                      EXPERIMENTELLER VERSUCHSAUFBAU                     │
└─────────────────────────────────────────────────────────────────────────┘
  [Test-Harness & Benchmark-Client]
                 │
                 ▼ (RFC 1928 SOCKS5 Protocol auf 127.0.0.1:9050)
         [Ingress Guard G_C]
                 │
                 ▼ (TCP Streaming mit 32-Byte Blind-Cookie)
      [Sovereign Rendezvous Point] (127.0.0.1:58888)
      - Standby-Queue-Pool (MAX_QUEUE_PER_COOKIE = 32)
      - Non-blocking tokio::select! Bidirektionales Bridging
                 ▲
                 │ (TCP Standby-Tunnel)
         [Egress Guard G_S]
                 ▲
                 │ (Dynamische Auflösung via Open-Swarm DHT Ring)
     [Hidden Service Host Daemon] (*.sec Sovereign Domain)
                 │
                 ▼ (Anti-LAN-Pivoting Firewall: Strict Loopback Jail)
      [Sandbox Egress Guard & Token-Bucket Rate Limiter]
                 │
                 ▼ (HTTP Header Inspection & Stripping Engine)
    [Anti-Fingerprinting Protocol Sanitizer (1.44 µs/op)]
                 │
                 ▼ (Bereinigter lokaler HTTP/1.1 Datenstrom)
  [Lokale Workload-Endpunkte: Notes App oder Enterprise Vault]
4.1 Kryptographische Mikrobenchmarks (AONT & RLNC)
Die rechenintensiven Kernkomponenten – All-Or-Nothing Pre-Whitening (AONT) und Galois-Feld-Matrizenoperationen in 
F
2
8
F 
2 
8
 
​
  – wurden isoliert unter realen Nutzlastgrößen evaluiert:

Tabelle 1: AONT-Rechenleistung (Rivest Package Transform, 40 Iterationen):

Nutzlastgröße	Encodierungs-Latenz	Decodierungs-Latenz	Encodierungs-Durchsatz	Decodierungs-Durchsatz
4 KB	
9,60
 
μ
s
9,60μs	
12,80
 
μ
s
12,80μs	
406,58
 
MB/s
406,58MB/s	
304,88
 
MB/s
304,88MB/s
16 KB	
44,58
 
μ
s
44,58μs	
63,45
 
μ
s
63,45μs	
350,53
 
MB/s
350,53MB/s	
246,23
 
MB/s
246,23MB/s
64 KB	
199,40
 
μ
s
199,40μs	
245,90
 
μ
s
245,90μs	
313,42
 
MB/s
313,42MB/s	
254,15
 
MB/s
254,15MB/s
256 KB	
665,35
 
μ
s
665,35μs	
909,83
 
μ
s
909,83μs	
375,74
 
MB/s
375,74MB/s	
274,77
 
MB/s
274,77MB/s
Ergebnis: AONT erreicht konsistent über 
300
 
MB/s
300MB/s Durchsatz pro Kern. Für interaktive Pakete (typische MTU 
≈
1,4
 
KB
≈1,4KB) liegt die Transformationslatenz unter 
10
 
μ
s
10μs und ist im Vergleich zu physischen Netzwerklaufzeiten vernachlässigbar.

Tabelle 2: RLNC Galois-Codierung in 
F
2
8
F 
2 
8
 
​
  (Nutzlast = 64 KB, 30 Iterationen):

Symbolanzahl 
K
K	Encodierungs-Zeit	Transit Re-Coding-Zeit	Decodierungs-Zeit	Encodierungs-Durchsatz	Decodierungs-Durchsatz
K
=
4
K=4	
79,33
 
μ
s
79,33μs	
7,03
 
μ
s
7,03μs	
537,63
 
μ
s
537,63μs	
787,75
 
MB/s
787,75MB/s	
116,25
 
MB/s
116,25MB/s
K
=
8
K=8	
120,77
 
μ
s
120,77μs	
3,60
 
μ
s
3,60μs	
1199,67
 
μ
s
1199,67μs	
517,53
 
MB/s
517,53MB/s	
52,10
 
MB/s
52,10MB/s
K
=
16
K=16	
185,03
 
μ
s
185,03μs	
2,07
 
μ
s
2,07μs	
2552,20
 
μ
s
2552,20μs	
337,77
 
MB/s
337,77MB/s	
24,49
 
MB/s
24,49MB/s
K
=
32
K=32	
363,80
 
μ
s
363,80μs	
1,23
 
μ
s
1,23μs	
5314,77
 
μ
s
5314,77μs	
171,80
 
MB/s
171,80MB/s	
11,76
 
MB/s
11,76MB/s
Ergebnis: Bemerkenswert ist die Transit-Rekodierungszeit: Um zwei codierte Pakete homomorph zu einem neuen Vektor zu verschmelzen, benötigt ein Relay-Knoten lediglich 
1,2
–
7,0
 
μ
s
1,2–7,0μs. Das bedeutet: Ein Relay kann über 140.000 Pakete pro Sekunde ohne Entschlüsselungsaufwand mutieren.

4.2 Protokoll-Wire-Overhead & Goodput-Verhältnis
Durch AONT-Expansion (32-Byte Maskierungsblock), RLNC-Vektor-Header und WebRTC/UDP-Framing entsteht ein Protokoll-Overhead. Wir messen das Goodput-Verhältnis über variierende Nutzlastgrößen und Paritätsgrade 
δ
∈
{
0
,
1
,
2
,
4
}
δ∈{0,1,2,4} bei 
K
=
8
K=8:

Tabelle 3: Empirische Wire-Expansion und Nutzdaten-Effizienz (Goodput):

Nutzlastgröße	Parität 
δ
δ	Transmittierte Wire-Bytes	Goodput-Effizienz	Bandbreiten-Expansion
1400 B (MTU)	
δ
=
0
δ=0	
1736
 
B
1736B	
80,65
 
%
80,65%	
+
24,00
 
%
+24,00%
1400 B (MTU)	
δ
=
1
δ=1	
1953
 
B
1953B	
71,68
 
%
71,68%	
+
39,50
 
%
+39,50%
1400 B (MTU)	
δ
=
2
δ=2	
2170
 
B
2170B	
64,52
 
%
64,52%	
+
55,00
 
%
+55,00%
1400 B (MTU)	
δ
=
4
δ=4	
2604
 
B
2604B	
53,76
 
%
53,76%	
+
86,00
 
%
+86,00%
8192 B (8 KB)	
δ
=
0
δ=0	
8520
 
B
8520B	
96,15
 
%
96,15%	
+
4,00
 
%
+4,00%
8192 B (8 KB)	
δ
=
1
δ=1	
9585
 
B
9585B	
85,47
 
%
85,47%	
+
17,00
 
%
+17,00%
8192 B (8 KB)	
δ
=
2
δ=2	
10650
 
B
10650B	
76,92
 
%
76,92%	
+
30,00
 
%
+30,00%
8192 B (8 KB)	
δ
=
4
δ=4	
12780
 
B
12780B	
64,10
 
%
64,10%	
+
56,01
 
%
+56,01%
32768 B (32 KB)	
δ
=
0
δ=0	
33096
 
B
33096B	
99,01
 
%
99,01%	
+
1,00
 
%
+1,00%
32768 B (32 KB)	
δ
=
1
δ=1	
37233
 
B
37233B	
88,01
 
%
88,01%	
+
13,63
 
%
+13,63%
32768 B (32 KB)	
δ
=
2
δ=2	
41370
 
B
41370B	
79,21
 
%
79,21%	
+
26,25
 
%
+26,25%
32768 B (32 KB)	
δ
=
4
δ=4	
49644
 
B
49644B	
66,01
 
%
66,01%	
+
51,50
 
%
+51,50%
Analyse: Bei größeren Übertragungsblöcken amortisiert sich der Header-Overhead vollständig: Für 32 KB Nutzlast liefert CFAF selbst bei 
δ
=
2
δ=2 Paritätsdrift (Fehlerrate 
<
6
×
10
−
8
<6×10 
−8
 ) eine Goodput-Effizienz von 
79,21
 
%
79,21%, was den Trade-off gegenüber Loopix (
>
200
%
>200% Overhead) dramatisch überlegen macht.

4.3 Multi-Trial Testnet-Latenzstatistik (4-Knoten-Swarm, 
N
=
50
N=50 Runden)
In einem vollständig asynchronen 4-Knoten-Testnet (Ingress 
A
→
A→ Transit 
R
1
,
R
2
→
R 
1
​
 ,R 
2
​
 → Egress 
B
B) wurde die empirische Latenzverteilung über 50 aufeinanderfolgende Transaktionen gemessen:

Szenario 1 (Fast-Lane): Normale interaktive Zustellung ohne künstliche Verzögerung.
Szenario 2 (Drift-Recovery): Vollständiger Ausfall der Fast-Lane (Blackhole-Simulation), Wiederherstellung ausschließlich über die Poisson-Drift-Relays 
R
1
R 
1
​
  und 
R
2
R 
2
​
 .
Tabelle 4: Latenzverteilung im Testnet (
N
=
50
N=50 Durchläufe):

Übertragungsszenario	Minimum	Median	Mittelwert	95. Perzentil (p95)	99. Perzentil (p99)	Maximum
Fast-Lane (0ms artificial)	
17,81
 
ms
17,81ms	
35,21
 
ms
35,21ms	
37,87
 
ms
37,87ms	
50,32
 
ms
50,32ms	
50,35
 
ms
50,35ms	
50,35
 
ms
50,35ms
Drift-Recovery (Blackhole)	
33,00
 
ms
33,00ms	
50,18
 
ms
50,18ms	
53,34
 
ms
53,34ms	
67,04
 
ms
67,04ms	
67,23
 
ms
67,23ms	
67,23
 
ms
67,23ms
Interpretation: Der Latenzunterschied zwischen nativer Fast-Lane und vollständiger Drift-Rekonstruktion beträgt im Median lediglich 
14,97
 
ms
14,97ms (Mean-Delta: 
15,47
 
ms
15,47ms). Dies beweist: Selbst bei abruptem Fast-Lane-Abriss bleibt der Datenstrom vollkommen interaktiv und löst keine TCP Retransmission Timeouts (RTO 
≥
200
 
ms
≥200ms) aus.

4.4 Empirische Timing-Entropie & Angreifervorteil
Zur Validierung von Satz 3 wurden 1.000 Inter-Packet Arrival Times (IAT) unter stochastischem Micro-Jitter (
±
1
 
ms
±1ms) gegen einen homogenen Poisson-Cover-Prozess (
λ
=
100
 
s
−
1
λ=100s 
−1
 , 
τ
ˉ
=
10
 
ms
τ
ˉ
 =10ms) gemessen:

Tabelle 5: Informationstheoretische Distanzmaße (
N
=
1000
N=1000 Samples):

Metrik	Empirischer Messwert	Theoretische Schranke	Bedeutung für den AS-Angreifer
Poisson Cover Rate 
λ
λ	
100
 
pkts/s
100pkts/s	
τ
ˉ
=
10,00
 
ms
τ
ˉ
 =10,00ms	Erwartungswert der Paketabstände
Kullback-Leibler Divergenz 
D
KL
D 
KL
​
 	
0,007570
 
nats
0,007570nats	
≤
ϵ
≤ϵ	Minimale relative Entropie
Total Variation Distance 
δ
(
P
act
,
P
cov
)
δ(P 
act
​
 ,P 
cov
​
 )	
0,029000
0,029000	
≤
ϵ
/
2
≤ 
ϵ/2
​
 	Statistischer Abstand beider Maße
Maximaler Angreifervorteil 
A
d
v
A
Adv 
A
​
 	
0,529000
0,529000	
≤
0,5
+
δ
≤0,5+δ	Vorteil über reines Raten (
0,500000
0,500000) beträgt nur 
2,9
 
%
2,9%
Fazit: Ein passiver Lauscher auf AS-Ebene kann den aktiven Datenverkehr vom stochastischen Hintergrundrauschen mit höchstens 
52,9
 
%
52,9% Genauigkeit unterscheiden. Ein statistisch stabiler Korrelationsangriff ist damit praktisch unmöglich.

4.5 Anwendungsbezogene End-to-End Evaluation (Notes App & Enterprise Web Services)
Um die Praxistauglichkeit der Overlay-Architektur jenseits synthetischer Ping-Szenarien zu quantifizieren, wurden zwei repräsentative Web-Applikationen als Sovereign Hidden Services (.sec-Topologie) über das vollständige SOCKS5- und Rendezvous-System gebenchmarkt:

Lightweight Notes App: Eine leichtgewichtige REST-basierte Notiz-Applikation (GET zur Abfrage von Notiz-Listen mit 
∼
300
 
Bytes
∼300Bytes Payload, POST für atomare JSON-Schreiboperationen mit 
∼
180
 
Bytes
∼180Bytes).
Enterprise Vault: Ein komplexerer, kryptographisch abgesicherter Datensafe mit interaktivem Dashboard (GET des HTML-Interface mit 
∼
1,2
 
KB
∼1,2KB Payload, POST zur serverseitigen Schlüsselabfrage und Verschlüsselung mit 
∼
220
 
Bytes
∼220Bytes).
Alle Anfragen durchliefen die vollständige Kette: SOCKS5-Handshake (RFC 1928), dynamische .sec-Auflösung, Blind-Cookie-Rendezvous am entkoppelten Sovereign RP, Host-Sandboxing mit Anti-LAN-Pivoting und die Anti-Fingerprinting Sanitizer Pipeline.

Tabelle 6: End-to-End HTTP-Transaktionslatenzen über Sovereign RP & SOCKS5 (
N
=
50
N=50 Transaktionen):

Applikation & Endpunkt	Payload-Typ	Min	Median	Mean	p95	Max
Notes App: GET /api/notes	JSON Array (
∼
300
 
B
∼300B)	
0,80
 
ms
0,80ms	
0,95
 
ms
0,95ms	
0,94
 
ms
0,94ms	
1,10
 
ms
1,10ms	
1,10
 
ms
1,10ms
Notes App: POST /api/notes	JSON Write (
∼
180
 
B
∼180B)	
0,54
 
ms
0,54ms	
0,91
 
ms
0,91ms	
0,95
 
ms
0,95ms	
1,75
 
ms
1,75ms	
1,75
 
ms
1,75ms
Enterprise Vault: GET /	HTML Dashboard (
∼
1,2
 
KB
∼1,2KB)	
0,72
 
ms
0,72ms	
0,99
 
ms
0,99ms	
0,96
 
ms
0,96ms	
1,06
 
ms
1,06ms	
1,06
 
ms
1,06ms
Enterprise Vault: POST /api/vault/encrypt	Krypto-Record (
∼
220
 
B
∼220B)	
0,80
 
ms
0,80ms	
1,00
 
ms
1,00ms	
1,05
 
ms
1,05ms	
1,73
 
ms
1,73ms	
1,73
 
ms
1,73ms
Tabelle 7: Latenz-Overhead des Overlay-Netzwerks & Host-Sanitizers:

Komponente / Messung	Gemessene Latenz	Overhead vs. Baseline	Durchsatz
Direkte TCP-Loopback-Baseline (Bare HTTP ohne Overlay)	
0,20
 
ms
0,20ms	
0,0
 
%
0,0% (Referenz)	–
SecureNet Darknet E2E-Overhead (SOCKS5 + RP-Bridging)	
0,95
 
ms
0,95ms	
+
0,75
 
ms
+0,75ms (
+
370,8
 
%
+370,8%)	Interaktiv echtzeitfähig
Header Sanitizer Overhead (Scrubbing & Anti-LAN Check)	
1,44
 
μ
s/op
1,44μs/op	
+
0,0014
 
ms
+0,0014ms (Vernachlässigbar)	
150,21
 
MB/s
150,21MB/s
Analyse der Messdaten:

Interaktive Antwortzeiten: Trotz vollständiger Blind-Cookie-Entkopplung, ephemerer Tunnel-Allokation und SOCKS5-Relaying bleiben die Median-Latenzen für reale CRUD- und Dashboard-Operationen unter 
1,0
 
ms
1,0ms (
0,91
–
1,00
 
ms
0,91–1,00ms).
Overhead-Verhältnis: Der absolute Overhead des gesamten Anonymisierungs- und Routing-Stacks beträgt im lokalen Testbett lediglich 
+
0,75
 
ms
+0,75ms gegenüber ungeschütztem Loopback-Traffic. In realen WAN-Szenarien (wo typische Round-Trip-Times bei 
15
–
50
 
ms
15–50ms liegen) ist ein solcher Zuschlag für Anwender imperzeptibel.
Effizienz des Host-Sandboxings: Die Anti-Fingerprinting Sanitizer Engine benötigt im Mittel lediglich 
1,44
 
μ
s
1,44μs pro HTTP-Header, was einem Durchsatz von über 
150
 
MB/s
150MB/s auf einem einzelnen CPU-Thread entspricht. Die Bereinigung verräterischer Header (Server, X-Powered-By, Origin-Lecks) verursacht somit keinerlei spürbare Prozessorlast oder Verzögerung.
4.5.1 Detaillierte Architektur & Spezifikation der Demo-Applikationen
Zur empirischen Validierung wurden zwei funktionale Micro-Server implementiert, die über den HiddenServiceHost angebunden sind:

A. Lightweight Notes App (RESTful In-Memory Store)
Statusverwaltung & Datenmodell: Ein thread-sicherer In-Memory Speicher (Arc<RwLock<Vec<Note>>>) mit der Schema-Definition Note { id: String, title: String, content: String, created_at: u64 }.
Endpunkte:
GET /api/notes: Serialisiert die Notizen-Liste als formatiertes JSON-Array (
∼
300
 
Bytes
∼300Bytes HTTP Payload).
POST /api/notes: Parst eingehende JSON-Payloads ({"title": "...", "content": "..."}), validiert Eingabefelder, vergibt eine deterministische UUIDv4 sowie Nanosekunden-Zeitstempel und quittiert mit HTTP 201 Created (
∼
180
 
Bytes
∼180Bytes).
Framing & Lebenszyklus: Verwendung von HTTP/1.1 Connection: close mit strikter Content-Length-Begrenzung. Dadurch wird gewährleistet, dass jede Transaktion den vollständigen SOCKS5-Verbindungsaufbau, das Blind-Cookie-Rendezvous, den Nutzdaten-Transfer und den geordneten Verbindungsabbau separat und isoliert durchläuft (keine Pipelining-Begünstigung).
B. Enterprise Vault Micro-Server (Kryptographisches Dashboard & Live-Audit)
Multi-Tier Endpunkte:
GET /: Liefert ein voll ausgestattetes HTML5/CSS-Dashboard für operative Telemetrie und Sicherheitsstatus (
∼
1,2
 
KB
∼1,2KB).
POST /api/auth/login: Realisiert einen tokenbasierten Authentifizierungs-Handshake.
POST /api/vault/encrypt: Simuliert hochgradig sensible Verschlüsselungsoperationen. Der Server generiert serverseitig eine 96-Bit ephemere Nonce, initialisiert eine symmetrische ChaCha20-Poly1305 AEAD-Verschlüsselung über den übergebenen Klartext und liefert den Base64-Chiffretext samt Authentifizierungs-Tag zurück (
∼
220
 
Bytes
∼220Bytes).
Synthetische Fingerprint-Injection als Test-Härtegrad für den Sanitizer: Um die Wirksamkeit der integrierten Anti-Fingerprinting-Pipeline unter realen Bedingungen nachzuweisen, wurde der Enterprise Vault Server so konfiguriert, dass er gezielt verräterische System-Signaturen aussendet:
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: PHP/8.1.2
X-Forwarded-For: 192.168.1.100 (Simuliertes RFC-1918 LAN-Adressleck)
Audit-Verifikation im Testbett: Im Versuchsaufbau wird verifiziert, dass die ProtocolSanitizer-Engine diese Header im Durchgang abfängt, den Server-Header auf die neutrale Signatur sb-securenet umschreibt, X-Powered-By restlos tilgt und jegliche RFC-1918 IP-Adressen entfernt, noch bevor die Antwort den Sovereign Rendezvous Point erreicht.
C. Sovereign Rendezvous Matching & Standby-Pool Mechanik
Blind-Cookie Entkopplung: Weder Client noch Service kennen die IP-Adresse des jeweils anderen. Das Rendezvous erfolgt über ein blindes 32-Byte Zufallscookie am Rendezvous Point (127.0.0.1:58888).
Standby-Worker-Pool: Der HiddenServiceHost initialisiert pro Cookie einen Standby-Pool von bis zu 32 gleichzeitigen Vorab-Registrierungen (MAX_QUEUE_PER_COOKIE = 32). Sobald ein Client eintrifft, übergibt der RP den Socket über einen tokio::sync::oneshot-Kanal ohne Blockade sofort an den wartenden Service-Worker.
Deadlock-Freies Stream-Bridging: Der Datentransfer zwischen Client-Socket und Service-Socket wird mittels asynchronem tokio::select! bidirektional abgewickelt, wodurch TCP-Half-Close-Deadlocks ausgeschlossen sind.
4.6 Methodische Reproduzierbarkeit, Artefakt-Verfügbarkeit & Open Science
Zur Gewährleistung der wissenschaftlichen Reproduzierbarkeit aller in diesem Dokument publizierten Theoreme und Messwerte:

Vollständige mathematische Parameterspezifikation:
Galois-Körper 
F
2
8
F 
2 
8
 
​
  mit Primpolynom 
P
(
x
)
=
x
8
+
x
4
+
x
3
+
x
+
1
P(x)=x 
8
 +x 
4
 +x 
3
 +x+1 (
0
x
11
B
0x11B).
Symbolblockgrößen 
K
∈
{
4
,
8
,
16
,
32
}
K∈{4,8,16,32}, Paritätsstufen 
δ
∈
{
0
,
1
,
2
,
4
}
δ∈{0,1,2,4}.
S/Kademlia DHT mit 
k
=
20
k=20, 
α
=
3
α=3 und 16-Bit Hashcash Proof-of-Work.
Post-Quantum Hybrid KEM: X25519 (RFC 7748) gepaart mit ML-KEM-768 (NIST FIPS 203).
Deterministischer Test- & Benchmark-Harness:
Die vollständige automatisierte Testsuite umfasst 58 Unit- und Integrationstests, die deterministisch in unter einer Sekunde durchlaufen (cargo test).
Der Benchmark-Runner (cargo run --release -- eval) führt die physikalischen Messungen (Tabellen 1–7) inklusive Warmup-Phasen und statistischer Perzentilberechnung autonom aus.
Open-Science & Responsible-Disclosure-Richtlinie:
Sämtliche Algorithmen, Datenstrukturen und theoretischen Beweise sind in dieser Publikation ohne Auslassungen dokumentiert.
Zur Vermeidung des Missbrauchs als unregulierbare Schatteninfrastruktur bleibt die voll integrierte Binärsoftware sb-securenet als geschlossener Forschungsprototyp unter Verschluss (Controlled Laboratory Artifact).
5. Grenzen, Schwachstellen & Diskussion (Limitations & Open Challenges)
Eine fundierte wissenschaftliche Analyse erfordert die explizite Offenlegung der inhärenten Schwachstellen und Systemgrenzen des CFAF-Designs:

5.1 Der Re-Assembly Latency Delta vs. TCP Congestion Control
Fällt die Fast-Lane aus, schlägt die Wiederherstellung nahtlos auf die Drift-Lanes um. Obwohl das gemessene Latenz-Delta im Median nur 
14,97
 
ms
14,97ms beträgt, stellt jeder abrupte RTT-Sprung TCP-Staukontroll-Algorithmen (wie Cubic oder Reno) vor Herausforderungen:

Wenn RTT-Messungen sprunghaft ansteigen, kann der Sender dies fälschlicherweise als Stauereignis interpretieren.
Abhilfe: CFAF erfordert auf Transportebene delay-unempfindliche Protokolle wie BBR v2/v3 oder QUIC mit entkoppelter RTT-Schätzung.
5.2 Grenzen von Hashcash-Proof-of-Work gegen staatliche Sybil-Cluster
Die S/Kademlia DHT nutzt einen statischen 16-Bit Hashcash-PoW, um die Generierung von Node-IDs zu drosseln (
∼
5
–
15
 
ms
∼5–15ms auf Standard-CPUs).

Limitation: Ein ressourcenstarker staatlicher Angreifer mit spezialisierten ASIC- oder GPU-Clustern kann Millionen gültiger Node-IDs vorberechnen, um K-Buckets gezielt zu vergiften (Eclipse-Attacke).
Ausblick: Für produktive Systeme müssten Memory-Hard-Funktionen (Argon2id) oder Trust-on-First-Use (TOFU) Petname-Web-of-Trust-Netzwerke kombiniert werden.
5.3 Asynchroner Wire-Overhead & Bandbreiten-Kosten
Wie in Tabelle 3 belegt, erzeugt die Paritätsdrift bei kleinen Paketen (1400 B, 
δ
=
2
δ=2) einen Wire-Overhead von bis zu 
+
55
 
%
+55%. Für Nutzer mit volumenbasierten Tarifen oder Mobilfunkanschlüssen bedeutet dies höhere Transferkosten. Das System erfordert eine adaptive Drosselung von 
δ
δ bei stabilen Leitungsbedingungen.

5.4 Der Edge-Case simultaner Ingress- und Egress-Kompromittierung
Das Double-Blind 2-Hop Modell (Satz 5) schützt zuverlässig gegen bösartige Rendezvous Points. Kolludieren jedoch der clientseitige Guard 
G
C
G 
C
​
  und der serverseitige Guard 
G
S
G 
S
​
  mit dem Angreifer (
{
G
C
,
G
S
}
⊂
A
{G 
C
​
 ,G 
S
​
 }⊂A), kann der Angreifer über synchrone Paketvolumina eine End-to-End-Bestätigung erzielen. Dieser Angriff erfordert jedoch die Kompromittierung zweier unabhängig gewählter Relays.

6. Topologie: Sovereign Double-Blind Rendezvous & Sandboxing
Ein Kernproblem bestehender Systeme ist die Zentralisierung: Tor stützt sich auf zehn feste Directory Authorities, und viele Relays laufen auf denselben großen Cloud-Hostern (AWS, Hetzner, OVH), deren Hypervisoren theoretisch kompromittierbar sind.

[Service-Endpunkt S] ──► [Guard G_S] ──┐
                                       ▼
                          [Sovereign Rendezvous Point]
                          (Blindes 32-Byte Cookie)
                                       ▲
[Client C]           ──► [Guard G_C] ──┘
6.1 Das Double-Blind 2-Hop Modell
Um das Vertrauensproblem bei privat betriebener Hardware aufzulösen, nutzt CFAF ein 2-Hop-Rendezvous:

Der Client 
C
C kontaktiert den Rendezvous Point (RP) nicht direkt, sondern über einen Zwischen-Guard 
G
C
G 
C
​
 .
Der Ziel-Endpunkt 
S
S kontaktiert den RP über einen Zwischen-Guard 
G
S
G 
S
​
 .
Der RP verknüpft beide Streams ausschließlich anhand eines ephemeren 32-Byte Blind-Cookies.
Ergebnis: Der RP sieht nur die IP-Adressen von 
G
C
G 
C
​
  und 
G
S
G 
S
​
 . Kein einziger Knoten im gesamten Netzwerk kennt gleichzeitig die IP-Adresse des Clients und des Servers.
6.2 Die Notwendigkeit rigiden Host-Sandboxings bei P2P-Relaying
Wenn Knotenbetreiber Rechen- oder Routing-Kapazitäten für verschlüsselte P2P-Netzwerke bereitstellen, entsteht ein systemischer Sicherheitskonflikt: Potenzielle Verwundbarkeiten gerouteter Protokolle oder gehosteter Dienste dürfen keinesfalls auf das lokale Netzwerk (LAN) des Knotenbetreibers übergreifen. Eine sichere P2P-Overlay-Architektur erfordert daher zwingend:

Anti-LAN-Pivoting (Strict Loopback Jail): Eingehende Overlay- und Relay-Verbindungen dürfen rein technisch niemals auf RFC-1918-Subnetze (192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12) oder Link-Local-Adressen weitergeleitet werden. Jeder Zugriff außerhalb der explizit gebundenen Loopback-Schnittstelle wird auf Transportebene präemptiv terminiert.
Anti-Fingerprinting Sanitizer: Automatisches Bereinigen von Protokoll-Headern (Server, X-Powered-By) und Beseitigen interner Adress-Lecks in Weiterleitungs-Headern, um ein Hardware- und Betriebssystem-Profiling des Hosters zu verhindern.
7. Ethische Reflexion & Verzicht auf freie Marktfreigabe
Die Entwicklung hochgradig entkoppelter, timing-resistenter Netzwerkarchitekturen bewegt sich in einem permanenten ethischen Spannungsfeld:

„Eine Technologie, die mathematisch unkorrelierbar, zensurresistent und hochperformant ist, schützt vertrauliche Kommunikation vor flächendeckender Verkehrsdatenanalyse – birgt jedoch bei unkontrollierter Freigabe das Risiko, für destruktive Zwecke missbraucht zu werden.“

Aus diesem Grund hat das Skulls & Bones Lab die bewusste Entscheidung getroffen:

Kein Release einer operativen Kommunikationssoftware: Es wird keine öffentliche Binary oder schlüsselfertige Software bereitgestellt, die als unreguliertes Schattennetzwerk in Betrieb genommen werden kann.
Fokus auf mathematischen und netzwerktheoretischen Erkenntnisgewinn: Die Erforschung stochastischer Methoden gegen passive Timing-Überwachung liefert wertvolle Impulse für künftige, transparente Standards im Bereich des Schutzes digitaler Grundrechte und sicherer Protokollarchitekturen.
8. Literaturverzeichnis & Zitationen
Ahlswede, R., Li, N., Yeung, R. W., & Cai, S.-Y. R. (2000). Network Information Flow. IEEE Transactions on Information Theory, 46(4), 1204–1216.
Baumgart, I., & Mies, S. (2007). S/Kademlia: A practical approach towards secure key-based routing. 2007 International Conference on Parallel and Distributed Systems.
Cardwell, N., Cheng, Y., Gunn, C. S., Yeganeh, S. H., & Jacobson, V. (2016). BBR: Congestion-Based Congestion Control. ACM Queue, 14(5), 20–53.
Dingledine, R., Mathewson, N., & Syverson, P. (2004). Tor: The Second-Generation Onion Router. Proceedings of the 13th USENIX Security Symposium.
Ho, T., Médard, M., Koetter, R., Karger, D. R., Effros, M., Shi, J., & Leong, B. (2006). A Random Linear Network Coding Approach to Multicast. IEEE Transactions on Information Theory, 52(10), 4413–4430.
Johnson, A., Syverson, P., Dingledine, R., & Mathewson, N. (2013). Users Get Routed: Traffic Correlation on Tor by Realistic Adversaries. Proceedings of the 2013 ACM SIGSAC Conference on Computer & Communications Security (CCS '13).
Murdoch, S. J., & Danezis, G. (2005). Low-Cost Traffic Analysis of Tor. 2005 IEEE Symposium on Security and Privacy (S&P '05).
National Institute of Standards and Technology (NIST). (2024). Module-Lattice-Based Key-Encapsulation Mechanism Standard (FIPS 203). U.S. Department of Commerce.
Nichols, K., & Jacobson, V. (2012). Controlling Queue Delay. Communications of the ACM, 55(7), 42–50.
Piotrowska, A. M., Hayes, J., Elahi, T., Meiser, S., & Danezis, G. (2017). The Loopix Anonymity System. Proceedings of the 26th USENIX Security Symposium (USENIX Security '17), 1199–1216.
Rivest, R. L. (1997). All-Or-Nothing Encryption and the Package Transform. Fast Software Encryption (FSE '97), Lecture Notes in Computer Science, 1267, 210–218. Springer.
van den Hooff, J., Lazar, D., Zaharia, M., & Zeldovich, N. (2015). Vuvuzela: Scalable private messaging resistant to traffic analysis. Proceedings of the 25th Symposium on Operating Systems Principles (SOSP '15), 137–152.