import { test, expect } from '@playwright/test';

test.describe('Homepage Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });  test('should load homepage successfully', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/Scott Obert/);
      // Check main content heading (handle different apostrophe types)
    await expect(page.locator('#hi-im-scott')).toContainText('Hi! I’m Scott');
    
    // Check meta description or main intro text
    await expect(page.locator('text=Principal Software Engineer')).toBeVisible();
  });

  test('should have proper meta tags for SEO', async ({ page }) => {
    // Check meta viewport
    const viewport = page.locator('meta[name="viewport"]');
    await expect(viewport).toHaveAttribute('content', /width=device-width/);
    
    // Check if there's a description meta tag
    const description = page.locator('meta[name="description"]');
    if (await description.count() > 0) {
      await expect(description).toHaveAttribute('content');
    }
  });
  test('should have navigation menu', async ({ page }) => {
    // Look for navigation element using semantic role
    await expect(page.getByRole('navigation')).toBeVisible();
  });
  test('should be responsive on mobile', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 }); // iPhone SE size
    
    // Check that main content is still visible
    await expect(page.locator('main h1, #hi-im-scott')).toBeVisible();
    await expect(page.locator('text=Principal Software Engineer')).toBeVisible();
  });
  test('should have working favicon', async ({ page }) => {
    // Check if favicon links exist
    const faviconElements = page.locator('link[rel*="icon"]');
    const count = await faviconElements.count();
    
    if (count > 0) {
      // Check that all favicon elements have valid href attributes
      for (let i = 0; i < count; i++) {
        const href = await faviconElements.nth(i).getAttribute('href');
        expect(href).toBeTruthy();
      }
    }
  });
});
