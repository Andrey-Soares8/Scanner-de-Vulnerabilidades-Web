class VulnerabilityScanner {
    constructor(targetUrl) {
        this.targetUrl = targetUrl;
        this.vulnerabilities = [];
    }

    async checkSecurityHeaders() {
        try {
            const response = await fetch(this.targetUrl, { method: 'HEAD' });
            const headers = response.headers;
            const securityHeaders = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ];
            securityHeaders.forEach(header => {
                if (!headers.get(header)) {
                    this.vulnerabilities.push(`Cabeçalho ausente: ${header}`);
                }
            });
        } catch (error) {
            console.error('Erro ao verificar cabeçalhos:', error);
        }
    }

    async scanAll() {
        await this.checkSecurityHeaders();
        return {
            targetUrl: this.targetUrl,
            vulnerabilitiesFound: this.vulnerabilities.length,
            vulnerabilities: this.vulnerabilities
        };
    }
}

async function iniciarScan() {
    const alvo = document.getElementById('alvo').value;
    const resultadoDiv = document.getElementById('resultadoScan');
    
    if (!alvo) {
        alert('Por favor, insira um alvo válido');
        return;
    }

    resultadoDiv.innerHTML = 'Escaneando... Por favor, aguarde.';
    
    try {
        const scanner = new VulnerabilityScanner(alvo);
        const resultados = await scanner.scanAll();
        
        let htmlResultado = `<p><strong>URL analisada:</strong> ${resultados.targetUrl}</p>`;
        htmlResultado += `<p><strong>Vulnerabilidades encontradas:</strong> ${resultados.vulnerabilitiesFound}</p>`;
        
        if (resultados.vulnerabilities.length > 0) {
            htmlResultado += '<ul>';
            resultados.vulnerabilities.forEach(vuln => {
                htmlResultado += `<li>${vuln}</li>`;
            });
            htmlResultado += '</ul>';
        } else {
            htmlResultado += '<p>Nenhuma vulnerabilidade encontrada!</p>';
        }
        
        resultadoDiv.innerHTML = htmlResultado;
    } catch (error) {
        resultadoDiv.innerHTML = 'Erro ao realizar o scan: ' + error.message;
    }
}