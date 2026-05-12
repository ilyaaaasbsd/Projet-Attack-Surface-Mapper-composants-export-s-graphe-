# ⚔️ Attack Surface Mapper

**Outil d'analyse de la surface d'attaque Android** — Scanne un APK ou un `AndroidManifest.xml` et génère un rapport complet : composants exportés, permissions sensibles, risques détectés, score de risque et graphe de dépendances Mermaid.

---

## 🎯 Objectif

Permettre à un analyste ou étudiant en sécurité mobile de cartographier rapidement la surface d'attaque d'une application Android à partir de son APK, sans outillage complexe.

---

## ✨ Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| 📦 Upload APK | Interface web drag & drop pour uploader un fichier `.apk` |
| ⚙️ Décompilation automatique | Utilisation d'`apktool` pour extraire le `AndroidManifest.xml` |
| 🧩 Analyse des composants | Activities, Services, Receivers, ContentProviders |
| 🔑 Permissions sensibles | Détection des permissions dangereuses déclarées |
| 🚨 Détection de risques | 10+ patterns de vulnérabilités Android |
| 📊 Surface Risk Score | Score 0-100 avec niveau LOW/MEDIUM/HIGH/CRITICAL |
| 🗺️ Graphe Mermaid | Graphe de dépendances APK → Manifest → Composants → Risques |
| 📋 Recommandations | Explication et correction pour chaque risque détecté |
| 🧪 Mode démo | Test immédiat avec un Manifest vulnérable exemple |

---

## 🚀 Installation

### 1. Prérequis Python

```powershell
# Créer l'environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt
```

### 2. Installation d'apktool (optionnel — requis pour les vrais APK)

**Option A — Téléchargement direct :**
1. Télécharger `apktool.jar` depuis https://apktool.org/
2. Créer un fichier `apktool.bat` dans un dossier du PATH :
   ```batch
   @echo off
   java -jar "C:\tools\apktool.jar" %*
   ```
3. S'assurer que Java est installé (`java -version`)

**Option B — Avec Chocolatey :**
```powershell
choco install apktool
```

**Option C — Sans apktool :**
L'application fonctionne en **mode démo** avec le Manifest vulnérable exemple, sans nécessiter apktool.

---

## ▶️ Démarrage

```powershell
# Se placer dans le dossier du projet
cd attack_surface_mapper_web

# Activer l'environnement virtuel
venv\Scripts\activate

# Lancer l'application Flask
python app.py
```

Ouvrir dans le navigateur : **http://127.0.0.1:5000**

---

## 🧪 Test sans APK (Mode Démo)

Accéder directement à : **http://127.0.0.1:5000/sample**

Cela analyse le fichier `samples/AndroidManifest_vulnerable.xml` qui contient intentionnellement :
- `android:debuggable="true"` (CRITICAL)
- `android:allowBackup="true"` (HIGH)
- `android:usesCleartextTraffic="true"` (HIGH)
- Permissions sensibles : INTERNET, READ_EXTERNAL_STORAGE, CAMERA, ACCESS_FINE_LOCATION, READ_CONTACTS
- `MainActivity` exportée sans permission
- `AdminActivity` exportée avec deep links HTTP/HTTPS et scheme custom
- `SyncService` exporté sans permission
- `BootReceiver` et `SmsReceiver` exportés
- `DataProvider` (ContentProvider) exporté sans permission
- `FileProvider` mal configuré (`grantUriPermissions="false"`)

---

## 🔍 Risques Détectés

| Pattern | Sévérité | Points |
|---|---|---|
| Application Debuggable | CRITICAL | 20 |
| ContentProvider exporté sans permission | CRITICAL | 20 |
| Backup ADB autorisé | HIGH | 12 |
| Trafic HTTP non chiffré | HIGH | 12 |
| Composant exporté sans permission | HIGH | 14 |
| ContentProvider sans read/write permission | HIGH | 18 |
| FileProvider mal configuré | HIGH | 14 |
| Intent-filter exposé sans permission | HIGH | 10 |
| Permission sensible | MEDIUM/HIGH | 3-6 |
| Deep link exposé | MEDIUM | 7 |

---

## 📁 Structure du projet

```
attack_surface_mapper_web/
├── app.py                          # Application Flask principale
├── requirements.txt                # Dépendances Python
├── README.md                       # Ce fichier
├── templates/
│   ├── index.html                  # Page d'accueil (upload)
│   └── result.html                 # Page résultats
├── static/
│   └── style.css                   # Styles CSS
├── uploads/                        # APK uploadés (temporaire)
├── workdir/                        # Dossiers de décompilation apktool
└── samples/
    └── AndroidManifest_vulnerable.xml   # Manifest d'exemple vulnérable
```

---

## 🎓 Démonstration devant le professeur

1. **Lancer l'application** : `python app.py`
2. **Ouvrir** : http://127.0.0.1:5000
3. **Mode démo** : Cliquer sur "Tester avec un Manifest vulnérable exemple" → http://127.0.0.1:5000/sample
4. **Montrer** :
   - Le score de risque CRITICAL (≥80)
   - La table des composants exportés
   - Le tableau des findings triés par sévérité
   - Le graphe Mermaid (APK → Manifest → Composants → Risques → Score)
   - Les recommandations de correction
5. **Avec un vrai APK** (si apktool installé) : uploader un APK depuis le formulaire

---

## 🛠️ Technologies

- **Backend** : Python 3.x + Flask
- **Frontend** : HTML5 + CSS3 + JavaScript vanilla
- **Graphe** : Mermaid.js v10
- **Extraction APK** : apktool
- **Parsing XML** : `xml.etree.ElementTree` (stdlib Python)

---

## ⚠️ Avertissement

Cet outil est destiné à un usage éducatif et à l'analyse de sécurité de vos propres applications. N'analysez que des APK dont vous êtes le propriétaire ou pour lesquels vous avez une autorisation explicite.
