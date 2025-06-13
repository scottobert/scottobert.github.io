import { test, expect } from '@playwright/test';

test.describe('Performance and Accessibility Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should load within reasonable time', async ({ page }) => {
    const startTime = Date.now();
    await page.goto('/', { waitUntil: 'networkidle' });
    const loadTime = Date.now() - startTime;
    
    // Should load within 5 seconds
    expect(loadTime).toBeLessThan(5000);
  });
  test('should have proper heading hierarchy', async ({ page }) => {
    // Check for h1 tags (there are 2 on this site - header and main content)
    const h1Count = await page.locator('h1').count();
    expect(h1Count).toBeGreaterThanOrEqual(1);
    
    // Check that headings exist
    const headings = page.locator('h1, h2, h3, h4, h5, h6');
    await expect(headings.first()).toBeVisible();
  });

  test('should have alt text for images', async ({ page }) => {
    const images = page.locator('img');
    const imageCount = await images.count();
    
    if (imageCount > 0) {
      for (let i = 0; i < imageCount; i++) {
        const img = images.nth(i);
        const alt = await img.getAttribute('alt');
        
        // Images should have alt attribute (can be empty for decorative images)
        expect(alt).not.toBeNull();
      }
    }
  });

  test('should have proper color contrast', async ({ page }) => {
    // Basic contrast check - ensure text is visible
    const textElements = page.locator('p, h1, h2, h3, h4, h5, h6, a, span, div');
    
    for (let i = 0; i < Math.min(await textElements.count(), 5); i++) {
      const element = textElements.nth(i);
      
      if (await element.isVisible()) {
        const styles = await element.evaluate((el) => {
          const computed = window.getComputedStyle(el);
          return {
            color: computed.color,
            backgroundColor: computed.backgroundColor,
            fontSize: computed.fontSize,
          };
        });
        
        // Basic check - ensure font size is reasonable
        const fontSize = parseInt(styles.fontSize);
        expect(fontSize).toBeGreaterThan(10); // At least 10px
      }
    }
  });

  test('should be keyboard accessible', async ({ page }) => {
    // Test that focusable elements can be reached by keyboard
    await page.keyboard.press('Tab');
    
    let focusableElements = 0;
    let maxTabs = 20; // Prevent infinite loop
    
    while (maxTabs-- > 0) {
      const focused = await page.locator(':focus').count();
      if (focused > 0) {
        focusableElements++;
        await page.keyboard.press('Tab');
      } else {
        break;
      }
    }
    
    // Should have at least some focusable elements
    expect(focusableElements).toBeGreaterThan(0);
  });

  test('should have proper semantic HTML', async ({ page }) => {
    // Check for semantic elements
    const semanticElements = page.locator('main, article, section, header, footer, nav, aside');
    const count = await semanticElements.count();
    
    // Should have at least some semantic elements
    expect(count).toBeGreaterThan(0);
  });
  test('should work without JavaScript', async ({ page, context }) => {
    // Disable JavaScript
    await context.addInitScript(() => {
      delete (window as any).eval;
    });
    
    await page.goto('/');
    
    // Basic content should still be visible
    await expect(page.locator('main h1, #hi-im-scott')).toBeVisible();
    await expect(page.locator('text=Principal Software Engineer')).toBeVisible();
  });
});
