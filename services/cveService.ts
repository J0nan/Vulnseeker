import { CVE } from '../types';

const BASE_URL = 'https://vulnerability.circl.lu/api';
const BROWSE_API_URL = 'https://cve.circl.lu/api';

const RESTRICTED_VERSION_SOURCES = ['fkie_nvd', 'nvd', 'variot'];

type CvssScores = {
  cvssV40: CvssMetricValue;
  cvssV31: CvssMetricValue;
  cvssV30: CvssMetricValue;
  cvssV20: CvssMetricValue;
};

type CvssMetricValue = {
  score: number | null;
  vector: string | null;
};

const emptyCvssMetricValue = (): CvssMetricValue => ({
  score: null,
  vector: null
});

const emptyCvssScores = (): CvssScores => ({
  cvssV40: emptyCvssMetricValue(),
  cvssV31: emptyCvssMetricValue(),
  cvssV30: emptyCvssMetricValue(),
  cvssV20: emptyCvssMetricValue()
});

const parseCvssScore = (value: any): number | null => {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string') {
    const parsed = parseFloat(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
};

const parseCvssVector = (value: any): string | null => {
  if (typeof value !== 'string') return null;

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
};

const keepHighestScore = (current: number | null, incoming: number | null): number | null => {
  if (incoming === null) return current;
  if (current === null || incoming > current) return incoming;
  return current;
};

const keepPreferredMetric = (current: CvssMetricValue, incoming: CvssMetricValue): CvssMetricValue => {
  if (incoming.score === null) {
    return current;
  }

  if (current.score === null || incoming.score > current.score) {
    return incoming;
  }

  if (incoming.score === current.score && current.vector === null && incoming.vector !== null) {
    return incoming;
  }

  return current;
};

const mergeCvssScores = (base: CvssScores, incoming: CvssScores): CvssScores => ({
  cvssV40: keepPreferredMetric(base.cvssV40, incoming.cvssV40),
  cvssV31: keepPreferredMetric(base.cvssV31, incoming.cvssV31),
  cvssV30: keepPreferredMetric(base.cvssV30, incoming.cvssV30),
  cvssV20: keepPreferredMetric(base.cvssV20, incoming.cvssV20)
});

const extractCvssFromMetricArray = (metricArray: any[]): CvssMetricValue => {
  if (!Array.isArray(metricArray)) return emptyCvssMetricValue();

  let score = emptyCvssMetricValue();
  for (const metric of metricArray) {
    const parsedScore = parseCvssScore(metric?.cvssData?.baseScore ?? metric?.baseScore);
    const parsedVector = parseCvssVector(metric?.cvssData?.vectorString ?? metric?.vectorString);
    score = keepPreferredMetric(score, {
      score: parsedScore,
      vector: parsedVector
    });
  }

  return score;
};

const extractCvssV5 = (metrics: any[]): CvssScores => {
  if (!Array.isArray(metrics)) return emptyCvssScores();

  let scores = emptyCvssScores();

  for (const m of metrics) {
    const metricScores: CvssScores = {
      cvssV40: {
        score: parseCvssScore(m?.cvssV4_0?.baseScore ?? m?.cvssV40?.baseScore ?? m?.cvssV4?.baseScore),
        vector: parseCvssVector(m?.cvssV4_0?.vectorString ?? m?.cvssV40?.vectorString ?? m?.cvssV4?.vectorString)
      },
      cvssV31: {
        score: parseCvssScore(m?.cvssV3_1?.baseScore ?? m?.cvssV31?.baseScore),
        vector: parseCvssVector(m?.cvssV3_1?.vectorString ?? m?.cvssV31?.vectorString)
      },
      cvssV30: {
        score: parseCvssScore(m?.cvssV3_0?.baseScore ?? m?.cvssV30?.baseScore),
        vector: parseCvssVector(m?.cvssV3_0?.vectorString ?? m?.cvssV30?.vectorString)
      },
      cvssV20: {
        score: parseCvssScore(m?.cvssV2_0?.baseScore ?? m?.cvssV20?.baseScore),
        vector: parseCvssVector(m?.cvssV2_0?.vectorString ?? m?.cvssV20?.vectorString)
      }
    };

    scores = mergeCvssScores(scores, metricScores);
  }

  return scores;
};

const extractLegacyCvss = (metrics: any): CvssScores => {
  if (!metrics) return emptyCvssScores();

  return {
    cvssV40: extractCvssFromMetricArray(metrics.cvssMetricV40 || metrics.cvssMetricV4),
    cvssV31: extractCvssFromMetricArray(metrics.cvssMetricV31),
    cvssV30: extractCvssFromMetricArray(metrics.cvssMetricV30),
    cvssV20: extractCvssFromMetricArray(metrics.cvssMetricV2)
  };
};

const getCvssFallbackScore = (scores: CvssScores): number | null => {
  if (scores.cvssV31.score !== null) return scores.cvssV31.score;
  if (scores.cvssV30.score !== null) return scores.cvssV30.score;
  if (scores.cvssV20.score !== null) return scores.cvssV20.score;
  return null;
};

const getPrimaryCvssScore = (scores: CvssScores, legacyScore: number | null = null): number | null => {
  return scores.cvssV40.score ?? getCvssFallbackScore(scores) ?? legacyScore;
};

// Helper to process raw API entries into CVE objects
const processEntries = (entries: any[], source: string): CVE[] => {
  return entries.map((entry: any[]) => {
    // entry is an array where index 0 is the ID key and index 1 is the data object
    const item = entry[1];
    if (!item) return null;

    // Detect if this is a CVE JSON 5.0 record (cvelistv5)
    const isV5 = !!item.cveMetadata;

    if (isV5) {
        const metadata = item.cveMetadata || {};
        const containers = item.containers || {};
        const cna = containers.cna || {};
        
        const id = metadata.cveId || 'Unknown ID';
        const vulnStatus = metadata.state; // e.g., PUBLISHED, REJECTED
        
        // Description: Try to find English description
        const descriptions = cna.descriptions || [];
        const summary = descriptions.find((d: any) => d.lang === 'en' || d.lang === 'en-US')?.value || descriptions[0]?.value || "No description available";
        
        // Dates
        const Published = metadata.datePublished || new Date().toISOString();
        const Modified = metadata.dateUpdated || new Date().toISOString();
        
        // CVSS Score Extraction
        // 1. Try CNA metrics
        let cvssScores = extractCvssV5(cna.metrics);
        
        // 2. If no CNA score, check Authorized Data Providers (ADP)
        if (containers.adp) {
            for (const adp of containers.adp) {
                const adpCvss = extractCvssV5(adp.metrics);
                cvssScores = mergeCvssScores(cvssScores, adpCvss);
            }
        }
        const cvss = getPrimaryCvssScore(cvssScores);
        
        // Configurations (CPEs or text description)
        const configs: string[] = [];
        
        if (cna.affected) {
            cna.affected.forEach((aff: any) => {
                // Try to use structured CPEs if available
                if (aff.cpes && Array.isArray(aff.cpes)) {
                    configs.push(...aff.cpes);
                } else {
                    // Fallback: Construct readable string from vendor/product/version
                    const vendor = aff.vendor && aff.vendor.toLowerCase() !== 'n/a' ? aff.vendor : '';
                    const product = aff.product && aff.product.toLowerCase() !== 'n/a' ? aff.product : '';
                    
                    if (vendor || product) {
                        if (aff.versions) {
                            aff.versions.forEach((v: any) => {
                                const version = v.version && v.version.toLowerCase() !== 'n/a' ? v.version : '';
                                if (version) {
                                    configs.push(`${vendor} ${product} ${version}`.trim());
                                } else {
                                    configs.push(`${vendor} ${product}`.trim());
                                }
                            });
                        } else {
                            configs.push(`${vendor} ${product}`.trim());
                        }
                    }
                }
            });
        }
        
        // References
        const references = cna.references?.map((ref: any) => ref.url).filter(Boolean) || [];

        return {
            id,
            summary,
            cvss,
            cvssV40: cvssScores.cvssV40.score,
            cvssV31: cvssScores.cvssV31.score,
            cvssV30: cvssScores.cvssV30.score,
            cvssV20: cvssScores.cvssV20.score,
            cvssVectorV40: cvssScores.cvssV40.vector,
            cvssVectorV31: cvssScores.cvssV31.vector,
            cvssVectorV30: cvssScores.cvssV30.vector,
            cvssVectorV20: cvssScores.cvssV20.vector,
            Published,
            Modified,
            vulnerable_configuration: Array.from(new Set(configs)), // Remove duplicates
            vulnerable_configuration_cpe_2_2: [],
            references,
            vulnStatus
        };
    }

    // Legacy/Other format fallback (e.g. fkie_nvd, cert-fr, jvndb, circl)
    const cvssScores = extractLegacyCvss(item.metrics);
    const legacyCvss = parseCvssScore(item.cvss);
    const cvss = getPrimaryCvssScore(cvssScores, legacyCvss);

    // Extract summary: check summary, title, or descriptions array
    const summary = item.summary || item.title || item.descriptions?.find((d: any) => d.lang === 'en')?.value || "No description available";

    const configs: string[] = [];
    
    if (item.configurations) {
       item.configurations.forEach((conf: any) => {
         conf.nodes?.forEach((node: any) => {
           node.cpeMatch?.forEach((match: any) => {
             if (match.criteria) configs.push(match.criteria);
           });
         });
       });
    } else if (item.vulnerable_configuration) {
        configs.push(...item.vulnerable_configuration);
    }

    return {
      id: item.id || item.cve_id || "Unknown ID",
      summary,
      cvss,
      cvssV40: cvssScores.cvssV40.score,
      cvssV31: cvssScores.cvssV31.score,
      cvssV30: cvssScores.cvssV30.score,
      cvssV20: cvssScores.cvssV20.score,
      cvssVectorV40: cvssScores.cvssV40.vector,
      cvssVectorV31: cvssScores.cvssV31.vector,
      cvssVectorV30: cvssScores.cvssV30.vector,
      cvssVectorV20: cvssScores.cvssV20.vector,
      Published: item.published || item.Published || new Date().toISOString(),
      Modified: item.lastModified || item.Modified || new Date().toISOString(),
      vulnerable_configuration: configs.length > 0 ? configs : [],
      vulnerable_configuration_cpe_2_2: [], 
      references: item.references?.map((ref: any) => typeof ref === 'string' ? ref : ref.url) || [],
      vulnStatus: item.vulnStatus
    } as CVE;
  }).filter((cve): cve is CVE => cve !== null);
};

// Cache for product lists to prevent redundant network calls
const productCache = new Map<string, string[]>();

/**
 * Searches for vendors matching the query string.
 * Uses the cve.circl.lu browse endpoint with the vendor query parameter.
 * @param query The partial vendor name
 * @returns Promise resolving to list of vendor names
 */
export const searchVendors = async (query: string): Promise<string[]> => {
  if (!query || query.length < 2) return [];

  // Use the search parameter to filter on the server side
  const url = `${BROWSE_API_URL}/browse/?vendor=${encodeURIComponent(query)}`;
  const proxyUrl = `https://cors.ja1712.workers.dev/?url=${encodeURIComponent(url)}`;
  
  try {
    const response = await fetch(proxyUrl);
    if (!response.ok) return [];
    
    const data = await response.json();
    
    // Check if data is an array (direct list of strings)
    if (Array.isArray(data)) {
        return data;
    }
    
    // Fallback if structure is { vendor: [...] }
    return data.vendor || [];
  } catch (error) {
    console.error("Error fetching vendors:", error);
    return [];
  }
};

/**
 * Gets all products for a specific vendor.
 * @param vendor The exact vendor name
 * @returns Promise resolving to list of product names
 */
export const getProductsByVendor = async (vendor: string): Promise<string[]> => {
  if (!vendor) return [];
  
  // Check cache first
  if (productCache.has(vendor)) {
      return productCache.get(vendor)!;
  }

  const url = `${BROWSE_API_URL}/browse/${encodeURIComponent(vendor)}`;
  const proxyUrl = `https://cors.ja1712.workers.dev/?url=${encodeURIComponent(url)}`;
  
  try {
    const response = await fetch(proxyUrl);
    if (!response.ok) return [];
    
    const data = await response.json();
    
    // Normalize response: API can return { product: [...] } or just [...]
    let products: string[] = [];
    
    if (Array.isArray(data)) {
        products = data;
    } else if (data.product && Array.isArray(data.product)) {
        products = data.product;
    }
    
    productCache.set(vendor, products);
    return products;
  } catch (error) {
    console.error("Error fetching products:", error);
    return [];
  }
};

/**
 * Searches for CVEs by vendor and product.
 * @param vendor The vendor name (e.g., "microsoft", "adobe")
 * @param product The product name (e.g., "office", "flash_player")
 * @returns Promise resolving to an array of CVEs
 */
export const searchCVEs = async (vendor: string, product: string): Promise<CVE[]> => {
  try {
    // Basic sanitization
    const safeVendor = encodeURIComponent(vendor.trim().toLowerCase());
    const safeProduct = encodeURIComponent(product.trim().toLowerCase());

    // Function to fetch a specific page
    const fetchPage = async (page: number = 1) => {
      let url = `${BASE_URL}/search/${safeVendor}/${safeProduct}`;
      
      // Append page query parameter if needed
      if (page > 1) {
        url += `?page=${page}`;
      }
      
      // The CIRCL API does not support CORS for direct browser requests.
      // We use a CORS proxy to bypass this restriction.
      const proxyUrl = `https://cors.ja1712.workers.dev/?url=${encodeURIComponent(url)}`;
      const response = await fetch(proxyUrl);
      
      if (!response.ok) {
        throw new Error(`API returned status: ${response.status}`);
      }
      return await response.json();
    };
    
    // 1. Fetch the first page to get data and pagination metadata
    const firstData = await fetchPage(1);
    
    // 2. Handle object format with 'results' property
    if (firstData.results) {
        // Map to store combined results and track if we have "trusted" (non-restricted) config data
        const resultsMap = new Map<string, { cve: CVE, hasTrustedConfig: boolean }>();
        
        // Helper to merge new CVEs into the map
        const mergeResults = (processedCVEs: CVE[], source: string) => {
            const isTrusted = !RESTRICTED_VERSION_SOURCES.includes(source.toLowerCase());

            processedCVEs.forEach(cve => {
                let entry = resultsMap.get(cve.id);
                if (!entry) {
                    const hasTrustedConfig = isTrusted && cve.vulnerable_configuration.length > 0;
                    resultsMap.set(cve.id, { cve, hasTrustedConfig });
                    return;
                }

                const existing = entry.cve;
                    
                // Summary Selection:
                // 1. Prefer cvelistv5 if valid
                // 2. Keep existing if valid
                // 3. Take new one if existing is invalid
                const isV5Source = source === 'cvelistv5';
                const newSummaryValid = cve.summary && cve.summary !== "No description available";
                const existingSummaryValid = existing.summary && existing.summary !== "No description available";

                if (isV5Source && newSummaryValid) {
                    existing.summary = cve.summary;
                    existing.vulnStatus = cve.vulnStatus;
                    existing.Published = cve.Published;
                    existing.Modified = cve.Modified;
                } else if (!existingSummaryValid && newSummaryValid) {
                        existing.summary = cve.summary;
                        // If we didn't have a good summary, we might not have had good dates either
                        if (!existing.Published || existing.Published === new Date().toISOString()) {
                        existing.Published = cve.Published;
                        }
                }
                
                // Update Status if we find one and didn't have one
                if (cve.vulnStatus && !existing.vulnStatus) {
                    existing.vulnStatus = cve.vulnStatus;
                }

                // Maximize CVSS (Keep the highest score found across all sources)
                const mergedCvssV40 = keepPreferredMetric(
                    {
                        score: existing.cvssV40 ?? null,
                        vector: existing.cvssVectorV40 ?? null
                    },
                    {
                        score: cve.cvssV40 ?? null,
                        vector: cve.cvssVectorV40 ?? null
                    }
                );
                existing.cvssV40 = mergedCvssV40.score;
                existing.cvssVectorV40 = mergedCvssV40.vector;

                const mergedCvssV31 = keepPreferredMetric(
                    {
                        score: existing.cvssV31 ?? null,
                        vector: existing.cvssVectorV31 ?? null
                    },
                    {
                        score: cve.cvssV31 ?? null,
                        vector: cve.cvssVectorV31 ?? null
                    }
                );
                existing.cvssV31 = mergedCvssV31.score;
                existing.cvssVectorV31 = mergedCvssV31.vector;

                const mergedCvssV30 = keepPreferredMetric(
                    {
                        score: existing.cvssV30 ?? null,
                        vector: existing.cvssVectorV30 ?? null
                    },
                    {
                        score: cve.cvssV30 ?? null,
                        vector: cve.cvssVectorV30 ?? null
                    }
                );
                existing.cvssV30 = mergedCvssV30.score;
                existing.cvssVectorV30 = mergedCvssV30.vector;

                const mergedCvssV20 = keepPreferredMetric(
                    {
                        score: existing.cvssV20 ?? null,
                        vector: existing.cvssVectorV20 ?? null
                    },
                    {
                        score: cve.cvssV20 ?? null,
                        vector: cve.cvssVectorV20 ?? null
                    }
                );
                existing.cvssV20 = mergedCvssV20.score;
                existing.cvssVectorV20 = mergedCvssV20.vector;

                const mergedLegacyCvss = keepHighestScore(existing.cvss ?? null, cve.cvss ?? null);
                existing.cvss = getPrimaryCvssScore(
                    {
                        cvssV40: mergedCvssV40,
                        cvssV31: mergedCvssV31,
                        cvssV30: mergedCvssV30,
                        cvssV20: mergedCvssV20
                    },
                    mergedLegacyCvss
                );
                
                // Config Merging Logic (Prioritize Trusted, Fallback to Restricted)
                if (isTrusted) {
                    if (cve.vulnerable_configuration.length > 0) {
                        // If we found trusted data, and we didn't have it before (e.g. only had NVD),
                        // we should overwrite/clear the restricted data to ensure purity.
                        if (!entry.hasTrustedConfig) {
                            existing.vulnerable_configuration = [];
                            entry.hasTrustedConfig = true;
                        }
                        // Union with other trusted sources (e.g. jvndb + cert-fr)
                        const combinedConfigs = new Set([...existing.vulnerable_configuration, ...cve.vulnerable_configuration]);
                        existing.vulnerable_configuration = Array.from(combinedConfigs);
                    }
                } else {
                    // Restricted Source (e.g. NVD)
                    // Only use if we DO NOT have trusted config data yet.
                    if (!entry.hasTrustedConfig && cve.vulnerable_configuration.length > 0) {
                        const combinedConfigs = new Set([...existing.vulnerable_configuration, ...cve.vulnerable_configuration]);
                        existing.vulnerable_configuration = Array.from(combinedConfigs);
                    }
                }

                // Union References
                const combinedRefs = new Set([...existing.references, ...cve.references]);
                existing.references = Array.from(combinedRefs);
            });
        };

        // Processing Logic:
        // We process Trusted sources first to establish the baseline.
        // Then we process Restricted sources to fill in gaps (fallback).
        const processSourceChunk = (resultsObj: any) => {
            const sources = Object.keys(resultsObj);
            const trustedSources = sources.filter(s => !RESTRICTED_VERSION_SOURCES.includes(s.toLowerCase()));
            const restrictedSources = sources.filter(s => RESTRICTED_VERSION_SOURCES.includes(s.toLowerCase()));

            trustedSources.forEach(source => {
                const entries = resultsObj[source];
                const processed = processEntries(entries, source);
                mergeResults(processed, source);
            });

            restrictedSources.forEach(source => {
                const entries = resultsObj[source];
                const processed = processEntries(entries, source);
                mergeResults(processed, source);
            });
        };

        // Process first page
        processSourceChunk(firstData.results);
      
      const totalCount = firstData.total_count || 0;
      const pageSize = firstData.page_size || 10;
      const totalPages = Math.ceil(totalCount / pageSize);

      // 3. If there are multiple pages, fetch the rest in parallel
      if (totalPages > 1) {
        const maxPages = 100; 
        const endPage = Math.min(totalPages, maxPages);
        const pagePromises = [];

        for (let p = 2; p <= endPage; p++) {
          pagePromises.push(fetchPage(p));
        }

        const pagesData = await Promise.all(pagePromises);
        
        // Aggregate results from all pages
        pagesData.forEach(data => {
          if (data.results) {
             processSourceChunk(data.results);
          }
        });
      }

      return Array.from(resultsMap.values()).map(entry => entry.cve);
    }
    
    // 4. Handle legacy array format (direct list of CVE objects)
    if (Array.isArray(firstData)) {
        return processEntries(firstData.map(item => [item.id, item]), 'legacy');
    }
    
    console.warn("Unrecognized API response structure", firstData);
    return [];
  } catch (error) {
    console.error("Error fetching CVEs:", error);
    throw error;
  }
};
