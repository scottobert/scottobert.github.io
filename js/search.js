// Search functionality using Lunr.js
class SearchHandler {
  constructor() {
    this.searchIndex = null;
    this.searchData = null;
    this.searchModal = null;
    this.searchInput = null;
    this.searchResults = null;
    this.isInitialized = false;
    
    this.init();
  }

  async init() {
    // Wait for DOM to be ready
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.setup());
    } else {
      this.setup();
    }
  }
  async setup() {
    try {
      // Load Lunr.js
      await this.loadLunr();
      
      // Load search data
      await this.loadSearchData();
      
      // Create search index
      this.createSearchIndex();
      
      // Setup UI
      this.setupUI();
      
      // Setup event listeners
      this.setupEventListeners();
      
      this.isInitialized = true;
      console.log('Search functionality initialized');
    } catch (error) {
      console.error('Failed to initialize search:', error);
      
      // Show a fallback message in the header if search button was added
    //   const existingButton = document.querySelector('.search-toggle');
    //   if (existingButton) {
    //     existingButton.style.opacity = '0.5';
    //     existingButton.title = 'Search temporarily unavailable';
    //     existingButton.setAttribute('disabled', 'true');
    //   }
    }
  }

  async loadLunr() {
    return new Promise((resolve, reject) => {
      if (window.lunr) {
        resolve();
        return;
      }

      const script = document.createElement('script');
      script.src = 'https://unpkg.com/lunr@2.3.9/lunr.min.js';
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
  }
  async loadSearchData() {
    try {
      const response = await fetch('/index.json');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const text = await response.text();
      
      // Try to parse the JSON, with error handling for malformed JSON
      try {
        this.searchData = JSON.parse(text);
      } catch (parseError) {
        console.error('Failed to parse search data JSON:', parseError);
        console.log('Response text:', text.substring(0, 500) + '...');
        throw new Error('Invalid JSON response from search index');
      }
      
      // Filter out any null or invalid entries
      this.searchData = this.searchData.filter(item => 
        item && item.title && item.href
      );
      
      console.log(`Loaded ${this.searchData.length} searchable items`);
    } catch (error) {
      console.error('Error loading search data:', error);
      throw error;
    }
  }  createSearchIndex() {
    if (!this.searchData || this.searchData.length === 0) {
      console.warn('No search data available for indexing');
      return;
    }

    try {
      const searchData = this.searchData; // Store reference for use in closure
      
      this.searchIndex = lunr(function() {
        this.ref('href');
        this.field('title', { boost: 10 });
        this.field('content', { boost: 5 });
        this.field('summary', { boost: 3 });
        this.field('tags', { boost: 2 });
        this.field('categories', { boost: 2 });
        this.field('series');

        searchData.forEach(function(doc) {
          // Ensure required fields exist
          if (doc && doc.href && doc.title) {
            this.add(doc);
          }
        }, this);
      });
      
      console.log('Search index created successfully');
    } catch (error) {
      console.error('Failed to create search index:', error);
      throw error;
    }
  }

  setupUI() {
    // Create search modal HTML
    const modalHTML = `
      <div id="search-modal" class="search-modal" style="display: none;">
        <div class="search-modal-overlay"></div>
        <div class="search-modal-content">
          <div class="search-modal-header">
            <input type="text" id="search-input" placeholder="Search posts, tags, categories..." autocomplete="off">
            <button id="search-close" class="search-close" aria-label="Close search">&times;</button>
          </div>
          <div id="search-results" class="search-results">
            <div class="search-instructions">
              <p>Start typing to search through posts, tags, and categories...</p>
              <div class="search-tips">
                <strong>Tips:</strong>
                <ul>
                  <li>Use quotes for exact phrases: <code>"serverless architecture"</code></li>
                  <li>Use + to require terms: <code>+AWS +Lambda</code></li>
                  <li>Use - to exclude terms: <code>TypeScript -JavaScript</code></li>
                  <li>Use * for wildcards: <code>server*</code></li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    `;

    // Add modal to body
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    // Get references
    this.searchModal = document.getElementById('search-modal');
    this.searchInput = document.getElementById('search-input');
    this.searchResults = document.getElementById('search-results');

    // Add search button to header
    this.addSearchButton();
  }  addSearchButton() {
    // Check if search button already exists in the HTML
    const existingButton = document.getElementById('search-toggle-btn');
    
    if (existingButton) {
      // Add click listener to the existing button
      existingButton.addEventListener('click', (e) => {
        e.preventDefault();
        this.openSearch();
      });
      
      console.log('Search button found and configured');
      return;
    }

    // Fallback: create button dynamically if it doesn't exist
    const nav = document.querySelector('.header-left nav');
    
    if (nav) {
      const searchButton = document.createElement('button');
      searchButton.className = 'search-toggle';
      searchButton.id = 'search-toggle-btn';
      searchButton.innerHTML = `
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
          <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
        </svg>
        <span>Search</span>
      `;
      searchButton.setAttribute('type', 'button');
      
      // Add the search button after the existing nav links
      nav.appendChild(searchButton);

      // Add click listener
      searchButton.addEventListener('click', (e) => {
        e.preventDefault();
        this.openSearch();
      });
      
      console.log('Search button created and added to navigation');
    } else {
      console.warn('Navigation element not found - search functionality not available');
    }
  }

  setupEventListeners() {
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      // Ctrl/Cmd + K to open search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        this.openSearch();
      }
      
      // Escape to close search
      if (e.key === 'Escape' && this.searchModal.style.display !== 'none') {
        this.closeSearch();
      }
    });

    // Search input listener
    this.searchInput.addEventListener('input', (e) => {
      this.performSearch(e.target.value);
    });

    // Close button listener
    document.getElementById('search-close').addEventListener('click', () => {
      this.closeSearch();
    });

    // Modal overlay listener
    this.searchModal.querySelector('.search-modal-overlay').addEventListener('click', () => {
      this.closeSearch();
    });

    // Prevent modal content clicks from closing modal
    this.searchModal.querySelector('.search-modal-content').addEventListener('click', (e) => {
      e.stopPropagation();
    });
  }

  openSearch() {
    if (!this.isInitialized) return;
    
    this.searchModal.style.display = 'block';
    document.body.style.overflow = 'hidden';
    
    // Focus search input after a brief delay
    setTimeout(() => {
      this.searchInput.focus();
    }, 100);
  }

  closeSearch() {
    this.searchModal.style.display = 'none';
    document.body.style.overflow = '';
    this.searchInput.value = '';
    this.showInstructions();
  }

  performSearch(query) {
    if (!query.trim()) {
      this.showInstructions();
      return;
    }

    try {
      const results = this.searchIndex.search(query);
      this.displayResults(results, query);
    } catch (error) {
      console.error('Search error:', error);
      this.displayError('Search error. Please try a different query.');
    }
  }

  displayResults(results, query) {
    if (results.length === 0) {
      this.searchResults.innerHTML = `
        <div class="search-no-results">
          <p>No results found for "<strong>${this.escapeHtml(query)}</strong>"</p>
          <p>Try different keywords or check the search tips above.</p>
        </div>
      `;
      return;
    }

    const resultsHTML = results.map(result => {
      const doc = this.searchData.find(d => d.href === result.ref);
      if (!doc) return '';

      return `
        <article class="search-result">
          <h3><a href="${doc.href}">${this.highlightText(doc.title, query)}</a></h3>
          <p class="search-result-summary">${this.highlightText(doc.summary || doc.content, query)}</p>
          <div class="search-result-meta">
            <time>${doc.date}</time>
            ${doc.tags ? `<span class="search-tags">${doc.tags.map(tag => `<span class="tag">${tag}</span>`).join('')}</span>` : ''}
            ${doc.series ? `<span class="search-series">Series: ${doc.series}</span>` : ''}
          </div>
        </article>
      `;
    }).join('');

    this.searchResults.innerHTML = `
      <div class="search-results-header">
        <p>Found ${results.length} result${results.length === 1 ? '' : 's'} for "<strong>${this.escapeHtml(query)}</strong>"</p>
      </div>
      <div class="search-results-list">
        ${resultsHTML}
      </div>
    `;
  }

  displayError(message) {
    this.searchResults.innerHTML = `
      <div class="search-error">
        <p>${message}</p>
      </div>
    `;
  }
  showInstructions() {
    this.searchResults.innerHTML = `
      <div class="search-instructions">
        <p>Start typing to search through posts, tags, and categories...</p>
        <div class="search-tips">
          <strong>Tips:</strong>
          <ul>
            <li>Use quotes for exact phrases: <code>"serverless architecture"</code></li>
            <li>Use + to require terms: <code>+AWS +Lambda</code></li>
            <li>Use - to exclude terms: <code>TypeScript -JavaScript</code></li>
            <li>Use * for wildcards: <code>server*</code></li>
          </ul>
        </div>
      </div>
    `;
  }
  highlightText(text, query) {
    if (!text || !query) return text;
    
    // Strip HTML tags to get plain text for highlighting
    const plainText = this.stripHtml(text);
    
    // Split query into individual terms (remove operators)
    const terms = query.split(/[\s\+\-\*\"]+/).filter(term => term.length > 2);
    
    let highlightedText = plainText;
    terms.forEach(term => {
      // Escape special regex characters in the term
      const escapedTerm = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(`(${escapedTerm})`, 'gi');
      highlightedText = highlightedText.replace(regex, '<mark>$1</mark>');
    });
    
    // Escape any remaining HTML characters for safety, but preserve our mark tags
    return this.escapeHtmlExceptMarks(highlightedText);
  }
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  stripHtml(text) {
    // Create a temporary div to strip HTML tags
    const div = document.createElement('div');
    div.innerHTML = text;
    return div.textContent || div.innerText || '';
  }

  escapeHtmlExceptMarks(text) {
    // First escape all HTML
    let escaped = this.escapeHtml(text);
    // Then restore the mark tags
    escaped = escaped.replace(/&lt;mark&gt;/g, '<mark>');
    escaped = escaped.replace(/&lt;\/mark&gt;/g, '</mark>');
    return escaped;
  }
}

// Initialize search when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => new SearchHandler());
} else {
  new SearchHandler();
}
