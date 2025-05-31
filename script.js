// script.js
// Header configuration data
const headersConfig = {
    'Content-Security-Policy': {
        icon: 'fas fa-lock',
        description: 'Defines approved sources of content that browsers may load.',
        vulnerabilities: ['Cross-Site Scripting (XSS)', 'Data Injection'],
        references: [
            'https://owasp.org/www-project-content-security-policy/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy'
        ],
        fixSnippets: {
            nginx: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self';\" always;",
            apache: "Header set Content-Security-Policy \"default-src 'self'\"",
            express: "const csp = require('helmet-csp');\napp.use(csp({\n  directives: {\n    defaultSrc: [\"'self'\"],\n    scriptSrc: [\"'self'\"]\n  }\n}));",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"Content-Security-Policy\" value=\"default-src 'self'\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'Strict-Transport-Security': {
        icon: 'fas fa-lock',
        description: 'Enforces secure (HTTP over SSL/TLS) connections to the server.',
        vulnerabilities: ['SSL Stripping', 'Man-in-the-Middle Attacks'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security'
        ],
        fixSnippets: {
            nginx: "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
            apache: "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"",
            express: "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"Strict-Transport-Security\" value=\"max-age=31536000; includeSubDomains; preload\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'X-Frame-Options': {
        icon: 'fas fa-window-maximize',
        description: 'Prevents clickjacking attacks by controlling if content can be embedded in frames.',
        vulnerabilities: ['Clickjacking', 'UI Redress Attacks'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options'
        ],
        fixSnippets: {
            nginx: "add_header X-Frame-Options \"DENY\" always;",
            apache: "Header always set X-Frame-Options \"DENY\"",
            express: "app.use(helmet.frameguard({ action: 'deny' }));",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"X-Frame-Options\" value=\"DENY\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'X-Content-Type-Options': {
        icon: 'fas fa-file',
        description: 'Prevents MIME type sniffing which can lead to security vulnerabilities.',
        vulnerabilities: ['MIME Sniffing', 'Content Type Confusion'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options'
        ],
        fixSnippets: {
            nginx: "add_header X-Content-Type-Options \"nosniff\" always;",
            apache: "Header always set X-Content-Type-Options \"nosniff\"",
            express: "app.use(helmet.noSniff());",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'Referrer-Policy': {
        icon: 'fas fa-eye',
        description: 'Controls how much referrer information is included in requests.',
        vulnerabilities: ['Referrer Leakage', 'Sensitive Data Exposure'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy'
        ],
        fixSnippets: {
            nginx: "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
            apache: "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
            express: "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"Referrer-Policy\" value=\"strict-origin-when-cross-origin\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'Permissions-Policy': {
        icon: 'fas fa-user-shield',
        description: 'Controls which browser features the site can use.',
        vulnerabilities: ['Unauthorized Feature Access', 'Privacy Violations'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
        ],
        fixSnippets: {
            nginx: "add_header Permissions-Policy \"geolocation=(), microphone=(), camera=()\" always;",
            apache: "Header always set Permissions-Policy \"geolocation=(), microphone=(), camera=()\"",
            express: "app.use(helmet.permittedCrossDomainPolicies());",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"Permissions-Policy\" value=\"geolocation=(), microphone=(), camera=()\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'Access-Control-Allow-Origin': {
        icon: 'fas fa-exchange-alt',
        description: 'Controls which sites can access the resource in a cross-origin request.',
        vulnerabilities: ['Cross-Origin Data Theft', 'CORS Misconfiguration'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin'
        ],
        fixSnippets: {
            nginx: "add_header Access-Control-Allow-Origin \"https://trusted.com\" always;",
            apache: "Header always set Access-Control-Allow-Origin \"https://trusted.com\"",
            express: "app.use(cors({ origin: 'https://trusted.com' }));",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"Access-Control-Allow-Origin\" value=\"https://trusted.com\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'Cross-Origin-Embedder-Policy': {
        icon: 'fas fa-cube',
        description: 'Prevents a document from loading any cross-origin resources that don\'t explicitly grant the document permission.',
        vulnerabilities: ['Cross-Site Script Inclusion', 'Resource Hijacking'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy'
        ],
        fixSnippets: {
            nginx: "add_header Cross-Origin-Embedder-Policy \"require-corp\" always;",
            apache: "Header always set Cross-Origin-Embedder-Policy \"require-corp\"",
            express: "app.use(helmet.crossOriginEmbedderPolicy());",
            iis: "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <add name=\"Cross-Origin-Embedder-Policy\" value=\"require-corp\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"
        }
    },
    'Set-Cookie': {
        icon: 'fas fa-cookie',
        description: 'Configures cookies with security attributes like HttpOnly, Secure, and SameSite.',
        vulnerabilities: ['Session Hijacking', 'Cross-Site Request Forgery'],
        references: [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie'
        ],
        fixSnippets: {
            nginx: "add_header Set-Cookie \"sessionid=123; Secure; HttpOnly; SameSite=Lax\" always;",
            apache: "Header always edit Set-Cookie \"(.*)\" \"$1; Secure; HttpOnly; SameSite=Lax\"",
            express: "app.use(session({\n  cookie: { \n    secure: true,\n    httpOnly: true,\n    sameSite: 'lax'\n  }\n}));",
            iis: "<system.web>\n  <httpCookies httpOnlyCookies=\"true\" requireSSL=\"true\" sameSite=\"Lax\" />\n</system.web>"
        }
    }
};

// Attack reference data
const attacksData = [
    {
        name: "Cross-Site Scripting (XSS)",
        severity: "Critical",
        description: "Attackers inject malicious scripts into web pages viewed by other users, which can steal cookies, session tokens, or other sensitive information.",
        prevention: ["Content-Security-Policy", "X-XSS-Protection"],
        reference: "https://owasp.org/www-community/attacks/xss/"
    },
    {
        name: "Clickjacking",
        severity: "High",
        description: "Attackers trick users into clicking something different from what they perceive, potentially leading to unauthorized actions.",
        prevention: ["X-Frame-Options", "Content-Security-Policy"],
        reference: "https://owasp.org/www-community/attacks/Clickjacking"
    },
    {
        name: "Man-in-the-Middle (MITM)",
        severity: "High",
        description: "Attackers intercept and potentially alter communication between two parties without their knowledge.",
        prevention: ["Strict-Transport-Security"],
        reference: "https://owasp.org/www-community/attacks/Manipulator-in-the-middle_attack"
    },
    {
        name: "Cross-Site Request Forgery (CSRF)",
        severity: "High",
        description: "Attackers trick users into performing actions they didn't intend to, using their authenticated sessions.",
        prevention: ["Set-Cookie (SameSite attribute)", "Custom CSRF Tokens"],
        reference: "https://owasp.org/www-community/attacks/csrf"
    },
    {
        name: "MIME Sniffing Attacks",
        severity: "Medium",
        description: "Browsers interpret files as different types than specified, potentially leading to code execution.",
        prevention: ["X-Content-Type-Options"],
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types#mime_sniffing"
    },
    {
        name: "Cross-Origin Data Leakage",
        severity: "Medium",
        description: "Unauthorized sites access sensitive data from other origins through browser features.",
        prevention: ["Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"],
        reference: "https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties"
    },
    {
        name: "Feature Abuse",
        severity: "Medium",
        description: "Malicious sites abuse browser features like geolocation, camera, or microphone without user consent.",
        prevention: ["Permissions-Policy"],
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Feature_Policy"
    },
    {
        name: "Referrer Leakage",
        severity: "Low",
        description: "Sensitive information is exposed through referrer headers when navigating to external sites.",
        prevention: ["Referrer-Policy"],
        reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    }
];

// DOM Elements
const urlInput = document.getElementById('url-input');
const scanBtn = document.getElementById('scan-btn');
const scanSpinner = document.getElementById('scan-spinner');
const headersGrid = document.getElementById('headers-grid');
const attackList = document.getElementById('attack-list');
const riskValue = document.getElementById('risk-value');
const headersChecked = document.getElementById('headers-checked');
const headersMissing = document.getElementById('headers-missing');
const headersVulnerable = document.getElementById('headers-vulnerable');
const exportBtn = document.getElementById('export-btn');
const fixModal = document.getElementById('fix-modal');
const closeModal = document.getElementById('close-modal');
const modalTitle = document.getElementById('modal-header-name');
const configCode = document.getElementById('config-code');
const copyBtn = document.getElementById('copy-btn');
const tabBtns = document.querySelectorAll('.tab-btn');
const configTabs = document.querySelectorAll('.config-tab');
const riskCircle = document.getElementById('risk-circle');
const websiteChips = document.querySelectorAll('.website-chip');

// Current analysis state
let currentAnalysis = null;
let currentHeaders = {};

// Initialize the application
function initApp() {
    renderAttackList();
    setupEventListeners();
    // Start with a scan of google.com
    setTimeout(scanHeaders, 500);
}

// Set up event listeners
function setupEventListeners() {
    scanBtn.addEventListener('click', scanHeaders);
    exportBtn.addEventListener('click', exportReport);
    closeModal.addEventListener('click', () => fixModal.classList.remove('active'));
    
    // Tab switching for attack panel
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            renderAttackList(btn.dataset.tab);
        });
    });
    
    // Configuration tab switching
    configTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            configTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            showConfigForServer(tab.dataset.server);
        });
    });
    
    copyBtn.addEventListener('click', copyConfigToClipboard);
    
    // Website suggestion chips
    websiteChips.forEach(chip => {
        chip.addEventListener('click', () => {
            urlInput.value = chip.dataset.url;
            scanHeaders();
        });
    });
    
    // Allow Enter key to trigger scan
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            scanHeaders();
        }
    });
}

// Render attack list
function renderAttackList(tab = 'attack') {
    attackList.innerHTML = '';
    
    if (tab === 'attack') {
        attacksData.forEach(attack => {
            const attackItem = document.createElement('div');
            attackItem.className = 'attack-item';
            attackItem.innerHTML = `
                <div class="attack-header">
                    <div class="attack-name">${attack.name}</div>
                    <div class="attack-severity">${attack.severity}</div>
                </div>
                <div class="attack-description">
                    ${attack.description}
                </div>
                <div class="prevention-headers">
                    ${attack.prevention.map(h => `<div class="header-tag">${h}</div>`).join('')}
                </div>
                <a href="${attack.reference}" target="_blank" class="reference-link">
                    <i class="fas fa-external-link-alt"></i> Learn More
                </a>
            `;
            attackList.appendChild(attackItem);
        });
    } else if (tab === 'reference') {
        // Render header references
        Object.keys(headersConfig).forEach(headerName => {
            const header = headersConfig[headerName];
            const attackItem = document.createElement('div');
            attackItem.className = 'attack-item';
            attackItem.innerHTML = `
                <div class="attack-header">
                    <div class="attack-name">${headerName}</div>
                </div>
                <div class="attack-description">
                    ${header.description}
                </div>
                <div class="prevention-headers">
                    <strong>Vulnerabilities:</strong> ${header.vulnerabilities.join(', ')}
                </div>
                <a href="${header.references[0]}" target="_blank" class="reference-link">
                    <i class="fas fa-external-link-alt"></i> Documentation
                </a>
            `;
            attackList.appendChild(attackItem);
        });
    } else {
        // Render CVEs
        const cves = [
            { id: 'CVE-2022-36327', severity: 'Critical', description: 'HTTP Security Header Misconfiguration Vulnerability' },
            { id: 'CVE-2021-44228', severity: 'Critical', description: 'Log4j Vulnerability Related to Header Injection' },
            { id: 'CVE-2020-3580', severity: 'High', description: 'CSP Bypass in Multiple Web Browsers' },
            { id: 'CVE-2019-11730', severity: 'High', description: 'Content Security Policy Bypass using Redirects' },
            { id: 'CVE-2018-8004', severity: 'Medium', description: 'Apache HTTP Server HTTP/2 Header Misconfiguration' }
        ];
        
        cves.forEach(cve => {
            const attackItem = document.createElement('div');
            attackItem.className = 'attack-item';
            attackItem.innerHTML = `
                <div class="attack-header">
                    <div class="attack-name">${cve.id}</div>
                    <div class="attack-severity">${cve.severity}</div>
                </div>
                <div class="attack-description">
                    ${cve.description}
                </div>
                <a href="https://nvd.nist.gov/vuln/detail/${cve.id}" target="_blank" class="reference-link">
                    <i class="fas fa-external-link-alt"></i> View Details
                </a>
            `;
            attackList.appendChild(attackItem);
        });
    }
}

// Scan headers for a given URL using HackerTarget API
async function scanHeaders() {
    const url = urlInput.value.trim();
    if (!url) return;
    
    // Show loading state
    scanBtn.disabled = true;
    scanSpinner.style.display = 'block';
    headersGrid.innerHTML = '<p class="initial-state"><i class="fas fa-spinner fa-spin"></i> Scanning website headers...</p>';
    
    try {
        // Construct API URL
        const apiUrl = `https://api.hackertarget.com/httpheaders/?q=${encodeURIComponent(url)}`;
        
        // Fetch headers using the API
        const response = await fetch(apiUrl);
        
        if (!response.ok) {
            throw new Error(`API returned status ${response.status}`);
        }
        
        // Get response text
        const data = await response.text();
        
        // Parse headers from response
        const headers = parseHeaders(data);
        currentHeaders = headers;
        
        // Analyze the headers
        currentAnalysis = analyzeHeaders(headers);
        
        // Render the results
        renderResults(currentAnalysis);
        
        // Update risk stats
        updateRiskStats(currentAnalysis);
        
    } catch (error) {
        console.error('Error scanning headers:', error);
        headersGrid.innerHTML = `
            <div class="error-state">
                <p><i class="fas fa-exclamation-triangle"></i> Error scanning website: ${error.message}</p>
                <p>Please ensure the URL is correct and accessible.</p>
                <p>Try using a different website or check your network connection.</p>
            </div>
        `;
    } finally {
        // Reset loading state
        scanBtn.disabled = false;
        scanSpinner.style.display = 'none';
    }
}

// Parse headers from HackerTarget response
function parseHeaders(text) {
    const headers = {};
    const lines = text.split('\n');
    
    for (const line of lines) {
        if (line.includes(':')) {
            const [key, value] = line.split(':').map(part => part.trim());
            if (key && value) {
                // Normalize header names to lowercase
                const normalizedKey = key.toLowerCase();
                
                // For Set-Cookie, we need to append multiple values
                if (normalizedKey === 'set-cookie') {
                    if (!headers[normalizedKey]) {
                        headers[normalizedKey] = [];
                    }
                    headers[normalizedKey].push(value);
                } else {
                    headers[normalizedKey] = value;
                }
            }
        }
    }
    
    // Convert Set-Cookie array to string if needed
    if (headers['set-cookie'] && Array.isArray(headers['set-cookie'])) {
        headers['set-cookie'] = headers['set-cookie'].join('; ');
    }
    
    return headers;
}

// Analyze headers against our configuration
function analyzeHeaders(headers) {
    const analysis = {};
    let secureCount = 0;
    let weakCount = 0;
    let missingCount = 0;

    Object.keys(headersConfig).forEach(headerName => {
        const headerKey = headerName.toLowerCase();
        const headerValue = headers[headerKey];
        const config = headersConfig[headerName];

        let status = 'missing';
        let risk = 'high';
        let value = null;

        if (headerValue) {
            value = headerValue;

            // Simple validation checks
            if (headerName === 'Content-Security-Policy') {
                status = headerValue.includes('unsafe') ? 'weak' : 'secure';
                risk = status === 'weak' ? 'medium' : 'low';
            } else if (headerName === 'Strict-Transport-Security') {
                status = headerValue.includes('max-age=31536000') ? 'secure' : 'weak';
                risk = status === 'weak' ? 'medium' : 'low';
            } else if (headerName === 'X-Frame-Options') {
                status = headerValue === 'DENY' ? 'secure' : 'weak';
                risk = status === 'weak' ? 'medium' : 'low';
            } else if (headerName === 'Set-Cookie') {
                const secure = headerValue.includes('Secure');
                const httpOnly = headerValue.includes('HttpOnly');
                const sameSite = headerValue.includes('SameSite') || headerValue.includes('SameSite=');
                status = secure && httpOnly && sameSite ? 'secure' : 'weak';
                risk = status === 'weak' ? 'medium' : 'low';
            } else {
                status = 'secure';
                risk = 'low';
            }

            if (status === 'secure') {
                secureCount++;
            } else {
                weakCount++;
            }
        } else {
            status = 'missing';
            risk = 'high';
            missingCount++;
        }

        analysis[headerName] = {
            status,
            risk,
            value,
            config
        };
    });

    // Calculate risk score
    const totalHeaders = Object.keys(headersConfig).length;
    const totalPoints = secureCount * 10 + weakCount * 5; // secure:10, weak:5, missing:0
    const maxPoints = totalHeaders * 10;
    const riskScore = Math.round((totalPoints / maxPoints) * 100);

    return {
        headers: analysis,
        stats: {
            checked: secureCount + weakCount,
            missing: missingCount,
            vulnerable: weakCount,
            riskScore
        }
    };
}

// Render analysis results
function renderResults(analysis) {
    const { headers, stats } = analysis;
    headersGrid.innerHTML = '';
    
    Object.keys(headers).forEach((headerName, index) => {
        const header = headers[headerName];
        const config = headersConfig[headerName];
        
        const card = document.createElement('div');
        card.className = `header-card status-${header.status === 'secure' ? 'safe' : 
                          header.status === 'weak' ? 'warning' : 'missing'} fade-in delay-${(index % 5) + 1}`;
        
        card.innerHTML = `
            <div class="card-header">
                <div class="header-title">
                    <div class="header-icon">
                        <i class="${config.icon}"></i>
                    </div>
                    <span>${headerName}</span>
                </div>
                <div class="status-badge ${header.status === 'secure' ? 'safe' : 
                      header.status === 'weak' ? 'warning' : 'missing'}">
                    ${header.status === 'secure' ? 'Secure' : 
                      header.status === 'weak' ? 'Weak' : 'Missing'}
                </div>
            </div>
            <div class="card-content">
                ${header.value ? header.value : config.description}
            </div>
            <div class="risk-level ${header.risk}">
                <i class="fas fa-${header.risk === 'high' ? 'exclamation-circle' : 
                   header.risk === 'medium' ? 'exclamation-triangle' : 'check-circle'}"></i>
                ${header.risk === 'high' ? 'High Risk' : 
                  header.risk === 'medium' ? 'Medium Risk' : 'Low Risk'}
            </div>
            <div class="card-footer">
                <button class="fix-btn" data-header="${headerName}">
                    Fix It
                </button>
            </div>
        `;
        
        // Add event listener to fix button
        const fixBtn = card.querySelector('.fix-btn');
        fixBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            showFixModal(headerName);
        });
        
        headersGrid.appendChild(card);
    });
}

// Show fix modal with configuration snippets
function showFixModal(headerName) {
    const config = headersConfig[headerName];
    if (!config) return;
    
    modalTitle.textContent = headerName;
    fixModal.classList.add('active');
    showConfigForServer('nginx'); // Default to nginx
    
    // Reset tabs
    configTabs.forEach(tab => tab.classList.remove('active'));
    document.querySelector('.config-tab[data-server="nginx"]').classList.add('active');
}

// Show configuration for a specific server
function showConfigForServer(server) {
    const config = headersConfig[modalTitle.textContent];
    if (!config || !config.fixSnippets[server]) return;
    
    configCode.textContent = config.fixSnippets[server];
}

// Update risk statistics
function updateRiskStats(analysis) {
    const { stats } = analysis;
    riskValue.textContent = `${stats.riskScore}%`;
    headersChecked.textContent = stats.checked;
    headersMissing.textContent = stats.missing;
    headersVulnerable.textContent = stats.vulnerable;
    
    // Update the risk circle
    riskCircle.style.background = `conic-gradient(
        var(--success) 0% ${stats.riskScore}%,
        var(--warning) ${stats.riskScore}% ${Math.min(stats.riskScore + 15, 100)}%,
        var(--danger) ${Math.min(stats.riskScore + 15, 100)}% 100%
    `;
}

// Copy configuration to clipboard
function copyConfigToClipboard() {
    const textarea = document.createElement('textarea');
    textarea.value = configCode.textContent;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    document.body.removeChild(textarea);
    
    // Show feedback
    const originalText = copyBtn.innerHTML;
    copyBtn.innerHTML = '<i class="fas fa-check"></i> Copied!';
    setTimeout(() => {
        copyBtn.innerHTML = originalText;
    }, 2000);
}

// Export report as HTML
function exportReport() {
    if (!currentAnalysis) {
        alert('Please scan a website first');
        return;
    }
    
    // For simplicity, we'll just save as HTML
    const content = generateReportContent();
    
    // Create a Blob and download
    const blob = new Blob([content], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `HeaderHunter-Report-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Generate report content
function generateReportContent() {
    const { headers, stats } = currentAnalysis;
    const url = urlInput.value;
    const date = new Date().toLocaleString();
    
    let html = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>HeaderHunter Pro Report - ${url}</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; }
                h1, h2 { color: #333; }
                .header-card { border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 5px; }
                .status-safe { border-left: 4px solid #238636; }
                .status-warning { border-left: 4px solid #d29922; }
                .status-missing { border-left: 4px solid #da3633; }
                .risk-level { font-weight: bold; }
                .risk-high { color: #da3633; }
                .risk-medium { color: #d29922; }
                .risk-low { color: #238636; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <h1>HeaderHunter Pro Security Report</h1>
            <p><strong>URL:</strong> ${url}</p>
            <p><strong>Date:</strong> ${date}</p>
            <p><strong>Security Score:</strong> ${stats.riskScore}%</p>
            
            <h2>Summary</h2>
            <table>
                <tr>
                    <th>Headers Checked</th>
                    <th>Missing Headers</th>
                    <th>Vulnerable Headers</th>
                    <th>Security Score</th>
                </tr>
                <tr>
                    <td>${stats.checked}</td>
                    <td>${stats.missing}</td>
                    <td>${stats.vulnerable}</td>
                    <td>${stats.riskScore}%</td>
                </tr>
            </table>
            
            <h2>Detailed Analysis</h2>
    `;
    
    Object.keys(headers).forEach(headerName => {
        const header = headers[headerName];
        const config = headersConfig[headerName];
        
        html += `
            <div class="header-card status-${header.status === 'secure' ? 'safe' : 
                          header.status === 'weak' ? 'warning' : 'missing'}">
                <h3>${headerName}</h3>
                <p><strong>Status:</strong> ${header.status === 'secure' ? 'Secure' : 
                      header.status === 'weak' ? 'Weak' : 'Missing'}</p>
                <p><strong>Value:</strong> ${header.value || 'Not present'}</p>
                <p class="risk-level risk-${header.risk}">
                    <strong>Risk Level:</strong> ${header.risk === 'high' ? 'High Risk' : 
                      header.risk === 'medium' ? 'Medium Risk' : 'Low Risk'}
                </p>
                <p><strong>Description:</strong> ${config.description}</p>
            </div>
        `;
    });
    
    html += `
            <h2>Recommendations</h2>
            <p>Based on the analysis, here are recommendations to improve security:</p>
            <ul>
                ${stats.missing > 0 ? '<li>Implement missing security headers</li>' : ''}
                ${stats.vulnerable > 0 ? '<li>Fix misconfigured headers with weak settings</li>' : ''}
                ${stats.riskScore < 80 ? '<li>Review all security headers for best practices</li>' : ''}
            </ul>
            
            <footer>
                <p>Generated by HeaderHunter Pro</p>
            </footer>
        </body>
        </html>
    `;
    
    return html;
}

// Initialize the application
initApp();