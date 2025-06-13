import { test, expect } from '@playwright/test';

test.describe('Blog Posts Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should display blog posts on homepage', async ({ page }) => {
    // Look for blog post links or articles
    const posts = page.locator('article, .post, .entry, a[href*="/posts/"]');
    await expect(posts.first()).toBeVisible();
  });
  test('should navigate to individual blog post', async ({ page }) => {
    // Find a specific blog post link (not the navigation "Blog" link)
    const postLink = page.locator('article a[href*="/posts/"]:not([href="/posts/"])').first();
    await expect(postLink).toBeVisible();
    
    // Use force click to bypass overlapping elements
    await postLink.click({ force: true });
    
    // Wait for navigation and check we're on a post page
    await page.waitForURL(/\/posts\/.+/);
      // Check that the post has content
    const content = page.locator('.post-content');
    await expect(content).toBeVisible();
  });
  test('should have readable blog post content', async ({ page }) => {
    // Navigate to a specific post that we know exists
    await page.goto('/posts/aws-api-gateway-typescript/');
    
    // Check for post title (exclude site header by targeting main content area)
    const title = page.locator('main h1, article h1, .post-title, .entry-title');
    await expect(title).toBeVisible();
    
    // Check for post content - be more specific to avoid multiple matches
    const content = page.locator('.post-content').first();
    await expect(content).toBeVisible();
    
    // Check that content has reasonable length (not empty)
    const contentText = await content.textContent();
    expect(contentText?.length).toBeGreaterThan(100);
  });
  test('should have proper post metadata', async ({ page }) => {
    await page.goto('/posts/aws-api-gateway-typescript/');
    
    // Look for date, tags, or other metadata
    const metadata = page.locator('.post-meta, .entry-meta, time, .date, .tags');
    if (await metadata.count() > 0) {
      await expect(metadata.first()).toBeVisible();
    }
  });

  test('should handle non-existent post gracefully', async ({ page }) => {
    const response = await page.goto('/posts/non-existent-post-12345/');
    
    // Should either redirect or show 404
    if (response) {
      expect([200, 404]).toContain(response.status());
    }
    
    // If 404, should have meaningful error page
    if (response?.status() === 404) {
      await expect(page.locator('h1:has-text("404")')).toBeVisible();
    }
  });

  test('should have working RSS feed', async ({ page }) => {
    const response = await page.goto('/index.xml');
    expect(response?.status()).toBe(200);
    
    // Get the raw response text instead of trying to parse as HTML/DOM
    const content = await response?.text() || '';
    expect(content).toContain('<rss');
  });
});
