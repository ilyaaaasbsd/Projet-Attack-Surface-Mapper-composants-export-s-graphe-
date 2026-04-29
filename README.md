# React + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the ESLint configuration

If you are developing a production application, we recommend using TypeScript with type-aware lint rules enabled. Check out the [TS template](https://github.com/vitejs/vite/tree/main/packages/create-vite/template-react-ts) for information on how to integrate TypeScript and [`typescript-eslint`](https://typescript-eslint.io) in your project.

#  Attack Surface Mapper - Android Manifest Security Audit

**Attack Surface Mapper (SEC-AUDIT v1.0)** est un outil d'analyse statique de sécurité conçu pour examiner les fichiers `AndroidManifest.xml`. Il permet aux développeurs et aux chercheurs en sécurité de visualiser rapidement la surface d'attaque d'une application Android, d'identifier les composants vulnérables et d'obtenir des recommandations de correction.



##  Fonctionnalités Principales

*   **Analyse Statique Locale :** L'analyse du `AndroidManifest.xml` se fait entièrement localement dans le navigateur, garantissant la confidentialité de vos données.
*   **Évaluation des Risques (Risk Scoring) :** Calcule un score global de sécurité sur 100 et définit un niveau de risque (CRITICAL, HIGH, MEDIUM, LOW).
*   **Extraction des Composants :** Identifie et liste automatiquement tous les composants de l'application (`Activities`, `Services`, `BroadcastReceivers`, `ContentProviders`).
*   **Détection des Vulnérabilités :** Met en évidence les composants exportés non sécurisés, les permissions manquantes et autres mauvaises pratiques de configuration.
*   **Graphique de Surface d'Attaque (Mermaid.js) :** Génération dynamique d'un graphe interactif illustrant les relations et les points d'entrée de l'application.
*   **Recommandations Pratiques :** Pour chaque faille identifiée, l'outil fournit le scénario d'attaque potentiel ainsi que le correctif recommandé avec du code d'exemple.


##  Technologies Utilisées

*   **Frontend :** React.js (via Vite)
*   **Stylisation :** CSS natif (Glassmorphism UI, thèmes sombres)
*   **Visualisation de graphes :** Mermaid.js (via CDN)
*   **Analyseur XML :** Parseur statique local personnalisé



##  Installation & Utilisation en Local

Si vous souhaitez exécuter ce projet localement sur votre machine :

### Prérequis
*   Avoir [Node.js](https://nodejs.org/) installé.

### Étapes
1. Cloner le repository :

   git clone https://github.com/ilyaaaasbsd/Projet-Attack-Surface-Mapper-composants-export-s-graphe-.git
   cd Projet-Attack-Surface-Mapper-composants-export-s-graphe-
