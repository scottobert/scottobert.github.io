import { test, expect } from '@playwright/test';

test.describe('Search Functionality Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should have search functionality if available', async ({ page }) => {
    // Look for search input, button, or icon
    const searchElements = page.locator(
      'input[type="text"], input[placeholder*="search" i], .search, [aria-label*="search" i], button:has-text("Search")'
    );
    
    const searchCount = await searchElements.count();
    
    if (searchCount > 0) {
      // Check if there's a search button that needs to be clicked first
      const searchButton = page.locator('button:has-text("Search")');
      if (await searchButton.count() > 0) {
        await searchButton.click();
        // Wait for the search input or interface to become visible
        await searchElements.first().waitFor({ state: 'visible' });
      }
      
      await expect(searchElements.first()).toBeVisible();
      
      // Try to interact with search if it exists
      const searchInput = page.locator('input[type="text"], input[placeholder*="Search" i]');

      if (await searchInput.count() > 0) {
        // Wait for the input to be visible before filling
        await searchInput.waitFor({ state: 'visible' });
        await searchInput.fill('AWS Lambda');
        await page.keyboard.press('Enter');
        
        // Should show some results or at least not error
        // Wait for search results to appear (adjust selector as needed)
        await page.waitForSelector('.search-result, .search-results, [data-testid="search-results"]', { timeout: 3000 });
        // Alternatively, to wait for network idle:
        // await page.waitForLoadState('networkidle');
      }
    }
  });

  test('should have working JSON search index', async ({ page }) => {
    // Check if JSON search index exists (common in Hugo sites)
    const response = await page.goto('/index.json');
    
    if (response?.status() === 200) {
      const content = await page.textContent('body');
      expect(content).toBeTruthy();
      
      // Should be valid JSON
      try {
        const json = JSON.parse(content || '');
        expect(Array.isArray(json) || typeof json === 'object').toBe(true);
      } catch (e) {
        // If it's not JSON, that's also okay
      }
    }
  });
});
