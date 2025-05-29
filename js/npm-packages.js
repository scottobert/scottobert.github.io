async function fetchNpmPackages() {
  try {
    // Try both with and without @ symbol to catch all packages
    const response = await fetch('https://registry.npmjs.org/-/v1/search?text=@scottobert&size=20');
    const data = await response.json();
    const packages = data.objects;
    
    const npmList = document.getElementById('npm-list');
    if (!packages || packages.length === 0) {
      npmList.innerHTML = '<p class="no-packages">No packages found</p>';
      return;
    }

    npmList.innerHTML = packages
      .map(pkg => {
        const p = pkg.package;
        return `
          <div class="npm-package">
            <h3>
              <a href="https://www.npmjs.com/package/${p.name}" target="_blank" rel="noopener noreferrer">
                ${p.name}
              </a>
            </h3>
            <div class="package-description">${p.description || ''}</div>
            <div class="package-meta">
              <span class="version">v${p.version}</span>
              ${p.links.repository ? `<a href="${p.links.repository}" class="repo-link" target="_blank" rel="noopener noreferrer">GitHub</a>` : ''}
            </div>
          </div>
        `;
      })
      .join('');
  } catch (error) {
    console.error('Error fetching NPM packages:', error);
    document.getElementById('npm-list').innerHTML = '<p class="error">Error loading packages</p>';
  }
}

// Load packages when the DOM is ready
document.addEventListener('DOMContentLoaded', fetchNpmPackages);
