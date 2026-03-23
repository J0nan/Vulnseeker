# VulnSeeker

VulnSeeker is a React + Vite frontend for searching CVEs by vendor and product. It uses CIRCL public CVE APIs and presents results with richer CVSS detail, sortable severity views, clickable severity filters, affected configuration data, and locally saved search snapshots.

## Overview

The application is designed for quick vulnerability triage in the browser:

- Search by vendor and product with autocomplete assistance
- Review CVE cards with CVSS scores, descriptions, publication dates, and affected configurations
- Compare results using separate CVSS v4.0 and fallback severity tracks
- Save, reload, import, and export result snapshots from browser storage

This repository contains the client application only. There is no custom backend service.

## Current Features

- **Vendor autocomplete** from CIRCL browse endpoints
- **Product suggestions by vendor** after selecting a vendor
- **CVE result cards** with:
  - plain-text CVE ID title
  - publication date and summary
  - known affected configurations
  - rejected-state indicator when applicable
  - separate **MITRE** and **NIST** external buttons
- **Per-result remove from view** control
- **Saved snapshots** stored in browser `localStorage`, including:
  - save current results
  - load a saved snapshot
  - rename or delete snapshots
  - clear all snapshots
  - import and export JSON snapshot files

## CVSS Handling, Sorting, and Filtering

Each result shows two CVSS tracks when data is available:

- **CVSS v4.0**
- **Fallback track** using `3.1 → 3.0 → 2.0`

Current UI behavior:

- Top statistics are split into two groups: one for **CVSS v4.0** and one for the **fallback track**
- Users can choose which track is used to **sort results**
- Severity statistic chips are **clickable filters**
- Selecting a severity chip also switches to that CVSS track for filtering/sorting context
- **All severities** clears the active severity filter
- Hovering or focusing a CVSS score reveals the associated **vector**
- Clicking a CVSS score copies the vector to the clipboard and shows user feedback

## Setup and Run

### Prerequisites

- **Node.js 18+**
- **npm**

### Install

```bash
npm install
```

### Start the development server

```bash
npm run dev
```

Default Vite dev server settings in this repository:

- Host: `0.0.0.0`
- Port: `3000`

### Build for production

```bash
npm run build
```

### Preview the production build

```bash
npm run preview
```

## Basic Usage

1. Enter at least 2 characters in **Vendor** to get suggestions.
2. Select a vendor to load related product suggestions.
3. Select or type a **Product** and run the search.
4. Review results, then optionally:
   - change the score sorting track
   - filter by severity from the statistics area
   - inspect or copy CVSS vectors from score badges
   - open the CVE on **MITRE** or **NIST**
   - remove individual CVEs from the current view
5. Save the result set as a snapshot if needed.

## Notes

- Data comes from the CIRCL CVE ecosystem, including:
  - `https://vulnerability.circl.lu/api`
  - `https://cve.circl.lu/api`
- Browser requests use a public CORS proxy in the client service layer.
- Saved snapshots are local to the current browser and are not synced across devices.
- The Vite base path is configured as `/Vulnseeker/`, which matters when deploying under a subpath.
- This project does not include authentication, accounts, or server-side persistence.
