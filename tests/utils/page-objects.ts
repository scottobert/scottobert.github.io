import { Page, expect } from '@playwright/test';

export class BasePage {
  constructor(protected page: Page) {}

  async goto(url: string = '/') {
    await this.page.goto(url);
  }

  async getTitle() {
    return await this.page.title();
  }

  async waitForLoad() {
    await this.page.waitForLoadState('networkidle');
  }

  async takeScreenshot(name: string) {
    await this.page.screenshot({ path: `test-results/${name}.png` });
  }

  async checkAccessibility() {
    // Basic accessibility checks
    const headings = this.page.locator('h1, h2, h3, h4, h5, h6');
    await expect(headings.first()).toBeVisible();

    // Check for alt text on images
    const images = this.page.locator('img');
    const imageCount = await images.count();
    
    for (let i = 0; i < imageCount; i++) {
      const img = images.nth(i);
      const alt = await img.getAttribute('alt');
      expect(alt).not.toBeNull();
    }
  }

  async checkResponsive() {
    // Test mobile view
    await this.page.setViewportSize({ width: 375, height: 667 });
    await this.waitForLoad();
    
    // Check that main content is still visible
    const mainContent = this.page.locator('main, .content, article');
    await expect(mainContent).toBeVisible();

    // Test tablet view
    await this.page.setViewportSize({ width: 768, height: 1024 });
    await this.waitForLoad();
    await expect(mainContent).toBeVisible();

    // Reset to desktop
    await this.page.setViewportSize({ width: 1200, height: 800 });
    await this.waitForLoad();
  }
}

export class HomePage extends BasePage {
  async expectToBeLoaded() {
    await expect(this.page.locator('main h1, #hi-im-scott')).toContainText("Hi! I'm Scott");
    await expect(this.page.locator('text=Principal Software Engineer')).toBeVisible();
  }
  async getBlogPosts() {
    return this.page.locator('a[href*="/posts/"]');
  }

  async clickFirstBlogPost() {
    const blogPosts = this.page.locator('a[href*="/posts/"]');
    const firstPost = blogPosts.first();
    await firstPost.click();
  }

  async getNavigation() {
    return this.page.locator('nav, .nav, .menu, header a');
  }
}

export class BlogPostPage extends BasePage {
  async expectToBeLoaded() {
    // Check for post title
    const title = this.page.locator('h1, .post-title, .entry-title');
    await expect(title).toBeVisible();
    
    // Check for post content
    const content = this.page.locator('main, article, .content, .post-content');
    await expect(content).toBeVisible();
  }

  async getPostTitle() {
    return this.page.locator('h1, .post-title, .entry-title').textContent();
  }

  async getPostContent() {
    return this.page.locator('main, article, .content, .post-content').textContent();
  }

  async getBreadcrumbs() {
    return this.page.locator('.breadcrumbs, .breadcrumb, nav[aria-label*="breadcrumb"]');
  }

  async getMetadata() {
    return this.page.locator('.post-meta, .entry-meta, time, .date, .tags');
  }
}
