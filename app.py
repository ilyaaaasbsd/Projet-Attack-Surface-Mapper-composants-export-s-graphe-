"""
Attack Surface Mapper - Application Flask
Analyse la surface d'attaque Android à partir d'un APK ou d'un AndroidManifest.xml
"""

import os
import shutil
import subprocess
import uuid
import xml.etree.ElementTree as ET
import zipfile
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.utils import secure_filename
from pathlib import Path

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['WORKDIR'] = 'workdir'
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB max

ANDROID_NS = '{http://schemas.android.com/apk/res/android}'

# Permissions sensibles Android
SENSITIVE_PERMISSIONS = {
    'android.permission.READ_EXTERNAL_STORAGE':    ('HIGH', 5),
    'android.permission.WRITE_EXTERNAL_STORAGE':   ('HIGH', 5),
    'android.permission.MANAGE_EXTERNAL_STORAGE':  ('HIGH', 6),
    'android.permission.READ_CONTACTS':            ('HIGH', 5),
    'android.permission.WRITE_CONTACTS':           ('HIGH', 5),
    'android.permission.ACCESS_FINE_LOCATION':     ('HIGH', 6),
    'android.permission.ACCESS_COARSE_LOCATION':   ('MEDIUM', 4),
    'android.permission.CAMERA':                   ('HIGH', 5),
    'android.permission.RECORD_AUDIO':             ('HIGH', 5),
    'android.permission.READ_SMS':                 ('HIGH', 6),
    'android.permission.SEND_SMS':                 ('HIGH', 6),
    'android.permission.RECEIVE_SMS':              ('HIGH', 6),
    'android.permission.READ_PHONE_STATE':         ('MEDIUM', 4),
    'android.permission.CALL_PHONE':               ('HIGH', 5),
    'android.permission.INTERNET':                 ('MEDIUM', 3),
}


# ─────────────────────────────────────────────
# Utilitaires
# ─────────────────────────────────────────────

def apktool_available():
    return Path("C:/apktool/apktool.jar").exists()


def android_attr(element, name):
    """Retourne la valeur d'un attribut Android en gérant le namespace."""
    return element.get(f'{ANDROID_NS}{name}')


def normalize_component_name(package_name, name):
    """Normalise le nom d'un composant Android (gère les noms relatifs)."""
    if not name:
        return name
    if name.startswith('.'):
        return package_name + name
    if '.' not in name:
        return f'{package_name}.{name}'
    return name


def validate_apk_file(apk_path):
    if not zipfile.is_zipfile(apk_path):
        raise RuntimeError("Le fichier uploadé n'est pas un APK valide.")

    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()
        if "AndroidManifest.xml" not in names:
            raise RuntimeError("AndroidManifest.xml introuvable dans l'APK.")

    return True


def validate_decoded_manifest(manifest_path):
    manifest_path = Path(manifest_path)

    if not manifest_path.exists():
        raise RuntimeError("AndroidManifest.xml introuvable après extraction apktool.")

    if manifest_path.stat().st_size == 0:
        raise RuntimeError("AndroidManifest.xml extrait est vide.")

    with open(manifest_path, "rb") as f:
        first_bytes = f.read(20)

    # Un vrai XML texte commence souvent par <?xml ou <manifest
    if not first_bytes.lstrip().startswith(b"<"):
        raise RuntimeError(
            "Le AndroidManifest.xml extrait n'est pas un XML texte valide. "
            "Il semble être encore en format binaire AXML. "
            "Il ne faut pas parser le Manifest brut depuis l'APK ; il faut le décoder avec apktool."
        )

    try:
        ET.parse(manifest_path)
    except ET.ParseError as e:
        raise RuntimeError(
            "Le AndroidManifest.xml extrait est invalide ou mal formé : " + str(e)
        )

    return True


def run_apktool(apk_path, output_dir):
    apktool_jar = Path("C:/apktool/apktool.jar")

    if not apktool_jar.exists():
        raise RuntimeError("apktool.jar introuvable dans C:/apktool/apktool.jar")

    if not Path(apk_path).exists():
        raise RuntimeError(f"APK introuvable : {apk_path}")

    output_dir = Path(output_dir)

    if output_dir.exists():
        shutil.rmtree(output_dir)

    cmd = [
        "java",
        "-jar",
        str(apktool_jar),
        "d",
        "-f",
        "--no-src",
        str(apk_path),
        "-o",
        str(output_dir)
    ]

    print("=== APKTOOL COMMAND ===")
    print(" ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
            shell=False
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "apktool a dépassé 180 secondes. "
            "Essayez avec un APK plus petit ou vérifiez que l'APK n'est pas protégé."
        )

    print("=== APKTOOL STDOUT ===")
    print(result.stdout)
    print("=== APKTOOL STDERR ===")
    print(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(
            "Erreur apktool.\n\nSTDOUT:\n"
            + result.stdout
            + "\n\nSTDERR:\n"
            + result.stderr
        )

    manifest_path = output_dir / "AndroidManifest.xml"

    validate_decoded_manifest(manifest_path)

    return manifest_path


# ─────────────────────────────────────────────
# Parsing du Manifest
# ─────────────────────────────────────────────

def parse_intent_filter(intent_filter):
    """Parse un élément intent-filter et retourne actions, catégories et deep links."""
    actions = []
    categories = []
    deep_links = []

    for action in intent_filter.findall('action'):
        a = android_attr(action, 'name')
        if a:
            actions.append(a)

    for cat in intent_filter.findall('category'):
        c = android_attr(cat, 'name')
        if c:
            categories.append(c)

    for data in intent_filter.findall('data'):
        scheme = android_attr(data, 'scheme') or ''
        host   = android_attr(data, 'host') or ''
        path   = android_attr(data, 'path') or android_attr(data, 'pathPrefix') or android_attr(data, 'pathPattern') or ''
        mime   = android_attr(data, 'mimeType') or ''

        if scheme in ('http', 'https') or (scheme and scheme not in ('content', 'file', '')):
            dl = {'scheme': scheme, 'host': host, 'path': path, 'mime': mime}
            dl['url'] = f'{scheme}://{host}{path}' if host else scheme
            deep_links.append(dl)

    return {
        'actions': actions,
        'categories': categories,
        'deep_links': deep_links,
    }


def parse_components(application, package_name):
    """Parse tous les composants Android d'un élément <application>."""
    components = []
    tag_type_map = {
        'activity':        'Activity',
        'activity-alias':  'Activity-Alias',
        'service':         'Service',
        'receiver':        'BroadcastReceiver',
        'provider':        'ContentProvider',
    }

    for tag, comp_type in tag_type_map.items():
        for elem in application.findall(tag):
            name       = normalize_component_name(package_name, android_attr(elem, 'name') or '')
            exported   = android_attr(elem, 'exported')
            permission = android_attr(elem, 'permission')
            read_perm  = android_attr(elem, 'readPermission')
            write_perm = android_attr(elem, 'writePermission')
            authorities    = android_attr(elem, 'authorities')
            grant_uri_perm = android_attr(elem, 'grantUriPermissions')

            intent_filters = []
            all_deep_links = []
            for ifilter in elem.findall('intent-filter'):
                parsed = parse_intent_filter(ifilter)
                intent_filters.append(parsed)
                all_deep_links.extend(parsed['deep_links'])

            has_intent_filter = len(intent_filters) > 0

            # Déterminer l'état exported
            if exported is None:
                if has_intent_filter:
                    exported_val = 'implicit (intent-filter)'
                    is_exported  = True
                else:
                    exported_val = 'false (default)'
                    is_exported  = False
            elif exported.lower() == 'true':
                exported_val = 'true'
                is_exported  = True
            else:
                exported_val = 'false'
                is_exported  = False

            components.append({
                'name':            name,
                'type':            comp_type,
                'exported':        exported_val,
                'is_exported':     is_exported,
                'permission':      permission,
                'read_permission': read_perm,
                'write_permission':write_perm,
                'authorities':     authorities,
                'grant_uri_perm':  grant_uri_perm,
                'has_intent_filter': has_intent_filter,
                'intent_filters':  intent_filters,
                'deep_links':      all_deep_links,
            })

    return components


# ─────────────────────────────────────────────
# Détection des risques
# ─────────────────────────────────────────────

def detect_risks(package_name, app_flags, permissions, components):
    """Détecte les patterns risqués et retourne une liste de findings."""
    findings = []

    def add(title, severity, component, reason, recommendation, points):
        findings.append({
            'title':          title,
            'severity':       severity,
            'component':      component,
            'reason':         reason,
            'recommendation': recommendation,
            'points':         points,
        })

    # 1. Application debuggable
    if app_flags.get('debuggable') == 'true':
        add(
            'Application Debuggable',
            'CRITICAL',
            package_name,
            'android:debuggable="true" permet à un attaquant de déboguer l\'application, '
            'd\'accéder à la mémoire, aux variables et d\'injecter du code via ADB.',
            'Supprimer android:debuggable ou le mettre à "false" dans le build de production. '
            'Utiliser BuildConfig.DEBUG pour les vérifications conditionnelles.',
            20
        )

    # 2. Backup autorisé
    if app_flags.get('allowBackup') != 'false':
        add(
            'Backup ADB Autorisé',
            'HIGH',
            package_name,
            'android:allowBackup="true" (ou absent) permet à quiconque ayant accès USB '
            'de sauvegarder et restaurer les données de l\'application via adb backup.',
            'Ajouter android:allowBackup="false" dans la balise <application> du Manifest.',
            12
        )

    # 3. Cleartext Traffic
    if app_flags.get('usesCleartextTraffic') == 'true':
        add(
            'Trafic HTTP Non Chiffré',
            'HIGH',
            package_name,
            'android:usesCleartextTraffic="true" autorise les communications HTTP non chiffrées, '
            'exposant les données à des attaques Man-in-the-Middle.',
            'Mettre android:usesCleartextTraffic="false" et forcer HTTPS pour toutes les communications. '
            'Définir une Network Security Config stricte.',
            12
        )

    # 4. Permissions sensibles
    for perm in permissions:
        if perm in SENSITIVE_PERMISSIONS:
            sev, pts = SENSITIVE_PERMISSIONS[perm]
            short = perm.replace('android.permission.', '')
            add(
                f'Permission Sensible : {short}',
                sev,
                perm,
                f'La permission {perm} donne accès à des données ou fonctionnalités sensibles. '
                f'Si elle n\'est pas strictement nécessaire, elle augmente la surface d\'attaque.',
                f'Vérifier si cette permission est réellement nécessaire. '
                f'Déclarer le principe du moindre privilège. Documenter l\'usage dans le README de sécurité.',
                pts
            )

    # 5. Composants exportés sans permission
    for comp in components:
        if not comp['is_exported']:
            continue

        ctype = comp['type']
        cname = comp['name'].split('.')[-1]
        perm  = comp['permission']

        # ContentProvider sans permission
        if ctype == 'ContentProvider':
            rp = comp.get('read_permission')
            wp = comp.get('write_permission')
            if not perm and not rp and not wp:
                add(
                    f'ContentProvider Exporté Sans Permission',
                    'CRITICAL',
                    comp['name'],
                    f'Le ContentProvider {cname} est exporté sans android:permission, '
                    f'readPermission ni writePermission. N\'importe quelle application peut lire/écrire ses données.',
                    'Ajouter android:readPermission et android:writePermission avec des permissions custom '
                    'de type signature ou signatureOrSystem.',
                    20
                )
            elif not perm:
                add(
                    f'ContentProvider Exporté Sans Permission Globale',
                    'HIGH',
                    comp['name'],
                    f'Le ContentProvider {cname} n\'a pas de permission globale. '
                    f'Seules read/write sont définies, ce qui peut laisser des vecteurs d\'attaque ouverts.',
                    'Ajouter android:permission en plus des readPermission/writePermission pour une protection complète.',
                    18
                )

            # FileProvider mal configuré
            n_lower = comp['name'].lower()
            auth_lower = (comp.get('authorities') or '').lower()
            if 'fileprovider' in n_lower or 'fileprovider' in auth_lower:
                if comp.get('grant_uri_perm') != 'true':
                    add(
                        'FileProvider Mal Configuré',
                        'HIGH',
                        comp['name'],
                        f'Le FileProvider {cname} n\'a pas android:grantUriPermissions="true". '
                        f'Cela peut exposer des fichiers internes à des applications tierces.',
                        'Ajouter android:grantUriPermissions="true" et définir un fichier res/xml/file_paths.xml '
                        'limitant les répertoires accessibles.',
                        14
                    )
        else:
            # Autres composants exportés sans permission
            if not perm:
                add(
                    f'{ctype} Exporté Sans Permission',
                    'HIGH',
                    comp['name'],
                    f'Le composant {cname} (type {ctype}) est accessible par toute application tierce '
                    f'sans nécessiter de permission. Cela peut mener à des abus ou de l\'élévation de privilèges.',
                    f'Ajouter android:permission avec une permission custom protégée par android:protectionLevel="signature". '
                    f'Si ce composant ne doit pas être public, mettre android:exported="false".',
                    14
                )

        # Intent-filter exposé sans permission
        if comp['has_intent_filter'] and not perm:
            if comp['is_exported'] and comp.get('exported') != 'false':
                if ctype not in ('ContentProvider',):  # déjà traité
                    add(
                        f'Intent-Filter Exposé Sans Permission',
                        'HIGH',
                        comp['name'],
                        f'{cname} possède un intent-filter et est accessible publiquement sans permission. '
                        f'Des applications malveillantes peuvent envoyer des intents arbitraires.',
                        'Ajouter android:permission ou supprimer l\'intent-filter si non nécessaire. '
                        'Valider et filtrer toutes les données reçues via les intents.',
                        10
                    )

        # Deep links exposés
        if comp['deep_links']:
            add(
                f'Deep Link Exposé',
                'MEDIUM',
                comp['name'],
                f'{cname} expose {len(comp["deep_links"])} deep link(s). Des applications malveillantes '
                f'peuvent déclencher ce composant via des liens URL personnalisés.',
                'Valider rigoureusement les paramètres des deep links. '
                'Ne pas exposer d\'actions sensibles via des deep links non authentifiés.',
                7
            )

    return findings


# ─────────────────────────────────────────────
# Score et niveau
# ─────────────────────────────────────────────

def calculate_score(findings, components, permissions):
    """Calcule le Surface Risk Score (0-100) et le niveau de risque."""
    total = sum(f['points'] for f in findings)

    # Pondération : composants exportés
    exported_count = sum(1 for c in components if c['is_exported'])
    if exported_count > 5:
        total += min((exported_count - 5) * 2, 10)

    # Pondération : nombre de permissions sensibles
    sensitive_count = sum(1 for p in permissions if p in SENSITIVE_PERMISSIONS)
    if sensitive_count > 3:
        total += min((sensitive_count - 3) * 1, 5)

    score = min(total, 100)

    if score >= 80:
        level = 'CRITICAL'
    elif score >= 55:
        level = 'HIGH'
    elif score >= 30:
        level = 'MEDIUM'
    else:
        level = 'LOW'

    return score, level


# ─────────────────────────────────────────────
# Génération du graphe Mermaid
# ─────────────────────────────────────────────

def sanitize_mermaid(text):
    """Nettoie une chaîne pour usage sûr dans Mermaid."""
    if not text:
        return 'unknown'
    return text.replace('"', "'").replace('<', '').replace('>', '').replace('&', 'and')[:60]


def generate_mermaid(package_name, components, findings, permissions, score, level):
    """Génère le code Mermaid (graph TD) représentant la surface d'attaque."""
    lines = ['graph TD']
    # NOTE : pas d'emojis dans les labels — ils cassent le parser Mermaid
    lines.append(f'    APK["APK : {sanitize_mermaid(package_name)}"]')
    lines.append(f'    MANIFEST["AndroidManifest.xml"]')
    lines.append(f'    APK --> MANIFEST')

    lines.append(f'    SCORE["Risk Score : {score}/100 - {level}"]')

    # Nœuds par type
    type_nodes = {}
    for comp_type in ['Activity', 'Activity-Alias', 'Service', 'BroadcastReceiver', 'ContentProvider']:
        comps_of_type = [c for c in components if c['type'] == comp_type]
        if comps_of_type:
            tid = comp_type.replace('-', '_').upper()
            type_nodes[comp_type] = tid
            lines.append(f'    {tid}["{comp_type} ({len(comps_of_type)})"]')
            lines.append(f'    MANIFEST --> {tid}')

    # Composants exportés
    exported_comps = [c for c in components if c['is_exported']]
    for i, comp in enumerate(exported_comps[:12]):
        cid = f'COMP_{i}'
        short_name = comp['name'].split('.')[-1]
        status = 'OPEN' if not comp['permission'] else 'PROTECTED'
        label = sanitize_mermaid(f'{short_name} [{status}]')
        lines.append(f'    {cid}["{label}"]')
        parent = type_nodes.get(comp['type'], 'MANIFEST')
        lines.append(f'    {parent} --> {cid}')

        # Deep links
        for j, dl in enumerate(comp['deep_links'][:2]):
            dlid = f'DL_{i}_{j}'
            url = sanitize_mermaid(dl.get('url', 'deep link'))
            lines.append(f'    {dlid}["DeepLink : {url}"]')
            lines.append(f'    {cid} --> {dlid}')

    # Permissions sensibles
    sensitive_perms = [p for p in permissions if p in SENSITIVE_PERMISSIONS]
    if sensitive_perms:
        lines.append(f'    PERMS["Permissions Sensibles ({len(sensitive_perms)})"]')
        lines.append(f'    MANIFEST --> PERMS')
        for i, p in enumerate(sensitive_perms[:6]):
            pid = f'PERM_{i}'
            short = p.replace('android.permission.', '')
            lines.append(f'    {pid}["{sanitize_mermaid(short)}"]')
            lines.append(f'    PERMS --> {pid}')

    # Findings critiques
    critical_findings = [f for f in findings if f['severity'] in ('CRITICAL', 'HIGH')][:6]
    if critical_findings:
        lines.append(f'    RISKS["Risques Detectes ({len(findings)})"]')
        lines.append(f'    MANIFEST --> RISKS')
        for i, f in enumerate(critical_findings):
            fid = f'RISK_{i}'
            sev = f['severity']
            title = sanitize_mermaid(f['title'])
            lines.append(f'    {fid}["{sev} : {title}"]')
            lines.append(f'    RISKS --> {fid}')
        lines.append(f'    RISKS --> SCORE')
    else:
        lines.append(f'    MANIFEST --> SCORE')

    # Styles
    lines.append('    style APK fill:#1a1a2e,color:#fff,stroke:#4ecca3')
    lines.append('    style MANIFEST fill:#16213e,color:#fff,stroke:#4ecca3')
    if level == 'CRITICAL':
        lines.append('    style SCORE fill:#c0392b,color:#fff,stroke:#e74c3c')
    elif level == 'HIGH':
        lines.append('    style SCORE fill:#e67e22,color:#fff,stroke:#f39c12')
    elif level == 'MEDIUM':
        lines.append('    style SCORE fill:#f39c12,color:#fff,stroke:#f1c40f')
    else:
        lines.append('    style SCORE fill:#27ae60,color:#fff,stroke:#2ecc71')

    return '\n'.join(lines)


# ─────────────────────────────────────────────
# Analyse principale
# ─────────────────────────────────────────────

def analyze_manifest(manifest_path):
    """Parse le AndroidManifest.xml et retourne le résultat complet de l'analyse."""
    tree = ET.parse(manifest_path)
    root = tree.getroot()

    package_name = root.get('package', 'unknown.package')

    # Permissions déclarées
    permissions = []
    for perm in root.findall('uses-permission'):
        pname = android_attr(perm, 'name')
        if pname:
            permissions.append(pname)

    # Balise <application>
    application = root.find('application')
    app_flags = {}
    if application is not None:
        app_flags = {
            'allowBackup':          android_attr(application, 'allowBackup'),
            'debuggable':           android_attr(application, 'debuggable'),
            'usesCleartextTraffic': android_attr(application, 'usesCleartextTraffic'),
            'networkSecurityConfig':android_attr(application, 'networkSecurityConfig'),
        }

    # Composants
    components = []
    if application is not None:
        components = parse_components(application, package_name)

    # Risques
    findings = detect_risks(package_name, app_flags, permissions, components)

    # Score
    score, level = calculate_score(findings, components, permissions)

    # Mermaid
    mermaid = generate_mermaid(package_name, components, findings, permissions, score, level)

    # Statistiques
    exported_comps = [c for c in components if c['is_exported']]
    stats = {
        'activities':  sum(1 for c in components if c['type'] in ('Activity', 'Activity-Alias')),
        'services':    sum(1 for c in components if c['type'] == 'Service'),
        'receivers':   sum(1 for c in components if c['type'] == 'BroadcastReceiver'),
        'providers':   sum(1 for c in components if c['type'] == 'ContentProvider'),
        'exported':    len(exported_comps),
        'permissions': len(permissions),
        'findings':    len(findings),
        'critical':    sum(1 for f in findings if f['severity'] == 'CRITICAL'),
        'high':        sum(1 for f in findings if f['severity'] == 'HIGH'),
        'medium':      sum(1 for f in findings if f['severity'] == 'MEDIUM'),
        'low':         sum(1 for f in findings if f['severity'] == 'LOW'),
    }

    return {
        'package_name': package_name,
        'permissions':  permissions,
        'app_flags':    app_flags,
        'components':   components,
        'findings':     findings,
        'score':        score,
        'level':        level,
        'mermaid':      mermaid,
        'stats':        stats,
    }


# ─────────────────────────────────────────────
# Routes Flask
# ─────────────────────────────────────────────

@app.route('/')
def index():
    """Page d'accueil avec formulaire d'upload."""
    return render_template('index.html', apktool_ok=apktool_available())


@app.route('/scan', methods=['POST'])
def scan():
    """Reçoit l'APK, le décompile et analyse le Manifest."""
    if 'apk_file' not in request.files:
        return render_template('index.html', apktool_ok=apktool_available(),
                               error='Aucun fichier sélectionné.')

    apk_file = request.files['apk_file']
    if not apk_file.filename or not apk_file.filename.lower().endswith('.apk'):
        return render_template('index.html', apktool_ok=apktool_available(),
                               error='Le fichier doit être un APK (.apk).')

    # Sauvegarder l'APK
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    filename   = secure_filename(apk_file.filename)
    apk_path   = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    apk_file.save(apk_path)

    # Dossier de travail unique
    job_id     = uuid.uuid4().hex[:8]
    output_dir = os.path.join(app.config['WORKDIR'], job_id)
    os.makedirs(output_dir, exist_ok=True)

    if not apktool_available():
        return render_template('index.html', apktool_ok=False,
                               error='apktool n\'est pas installé. '
                                     'Installez apktool et relancez l\'application. '
                                     'Vous pouvez utiliser le mode démo avec le Manifest vulnérable exemple.')

    try:
        validate_apk_file(apk_path)
        manifest_path = run_apktool(apk_path, output_dir)
        result = analyze_manifest(manifest_path)
        result['apk_name'] = filename
        result['mode'] = 'apk'
        return render_template('result.html', **result)
    except Exception as e:
        return render_template('index.html', apktool_ok=apktool_available(),
                               error=f'Erreur lors de l\'analyse : {str(e)}')


@app.route('/sample')
def sample():
    """Analyse le Manifest vulnérable exemple (mode test sans APK)."""
    sample_path = os.path.join('samples', 'AndroidManifest_vulnerable.xml')
    if not os.path.exists(sample_path):
        return render_template('index.html', apktool_ok=apktool_available(),
                               error='Fichier exemple introuvable.')
    try:
        result = analyze_manifest(sample_path)
        result['apk_name'] = 'AndroidManifest_vulnerable.xml (exemple)'
        result['mode'] = 'sample'
        return render_template('result.html', **result)
    except Exception as e:
        return render_template('index.html', apktool_ok=apktool_available(),
                               error=f'Erreur lors de l\'analyse exemple : {str(e)}')


if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('workdir', exist_ok=True)
    app.run(debug=True, host='0.0.0.0', port=5000)
