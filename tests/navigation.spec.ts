import { test, expect } from '@playwright/test';

test.describe('Navigation Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should have working site navigation', async ({ page }) => {
    // Look for navigation menu
    const nav = page.locator('nav');
    await expect(nav).toBeVisible();
    
    // Check if there are navigation links
    const navLinks = page.locator('nav a');
    const linkCount = await navLinks.count();
    expect(linkCount).toBeGreaterThan(0);
  });
  test('should navigate to About page if it exists', async ({ page }) => {
    const aboutLink = page.locator('a[href*="about"], a:has-text("About")');
    
    if (await aboutLink.count() > 0) {
      await aboutLink.click();
      await page.waitForURL(/about/);
      
      // Check that about page loads
      await expect(page.locator('main, .content')).toBeVisible();
    } else {
      // Skip this test if no about page exists
      console.log('No About page found, skipping test');
    }
  });
  test('should have working logo/site title link', async ({ page }) => {
    // Look for site logo or title that should link to home
    const logoLink = page.locator('header h1 a, .header h1 a, .site-title a');
    
    if (await logoLink.count() > 0) {
      // Navigate to a different page first
      await page.goto('/posts/aws-api-gateway-typescript/');
      
      // Click logo/title to go back to home
      await logoLink.first().click();
      await page.waitForURL('/');
      
      // Verify we're back on homepage
      await expect(page.locator('main h1, #hi-im-scott')).toContainText("Hi! I’m Scott");
    }
  });
  test('should have working breadcrumbs on post pages', async ({ page }) => {
    await page.goto('/posts/aws-api-gateway-typescript/');
    
    // Look for breadcrumbs
    const breadcrumbs = page.locator('.breadcrumbs, .breadcrumb, nav[aria-label*="breadcrumb"]');
    
    if (await breadcrumbs.count() > 0) {
      await expect(breadcrumbs).toBeVisible();
      
      // Check for home link in breadcrumbs
      const homeLink = breadcrumbs.locator('a[href="/"], a:has-text("Home")');
      if (await homeLink.count() > 0) {
        await expect(homeLink).toBeVisible();
      }
    }
  });

  test('should handle keyboard navigation', async ({ page }) => {
    // Test tab navigation through interactive elements
    await page.keyboard.press('Tab');
    
    // Check that focus is visible (should have focus indicator)
    const focusedElement = page.locator(':focus');
    await expect(focusedElement).toBeVisible();
  });
});
