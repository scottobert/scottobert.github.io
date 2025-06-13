import { Page } from '@playwright/test';

/**
 * Utility functions for E2E testing
 */

export async function waitForPageLoad(page: Page, timeout: number = 30000) {
  await page.waitForLoadState('networkidle', { timeout });
}

export async function scrollToBottom(page: Page) {
  await page.evaluate(() => {
    window.scrollTo(0, document.body.scrollHeight);
  });
}

export async function scrollToTop(page: Page) {
  await page.evaluate(() => {
    window.scrollTo(0, 0);
  });
}

export async function getPagePerformanceMetrics(page: Page) {
  return await page.evaluate(() => {
    const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
    return {
      domContentLoaded: navigation.domContentLoadedEventEnd - navigation.domContentLoadedEventStart,
      loadComplete: navigation.loadEventEnd - navigation.loadEventStart,
      firstPaint: performance.getEntriesByName('first-paint')[0]?.startTime || 0,
      firstContentfulPaint: performance.getEntriesByName('first-contentful-paint')[0]?.startTime || 0,
    };
  });
}

export async function checkConsoleErrors(page: Page): Promise<string[]> {
  const errors: string[] = [];
  
  page.on('console', (message) => {
    if (message.type() === 'error') {
      errors.push(message.text());
    }
  });

  return errors;
}

export async function simulateSlowNetwork(page: Page) {
  const client = await page.context().newCDPSession(page);
  await client.send('Network.enable');
  await client.send('Network.emulateNetworkConditions', {
    offline: false,
    downloadThroughput: 200 * 1024, // 200 KB/s
    uploadThroughput: 200 * 1024,   // 200 KB/s
    latency: 100,
  });
}

export async function resetNetworkConditions(page: Page) {
  const client = await page.context().newCDPSession(page);
  await client.send('Network.disable');
}

export const viewports = {
  mobile: { width: 375, height: 667 },
  tablet: { width: 768, height: 1024 },
  desktop: { width: 1200, height: 800 },
  largeDesktop: { width: 1920, height: 1080 },
} as const;

export async function testViewport(page: Page, viewport: keyof typeof viewports) {
  await page.setViewportSize(viewports[viewport]);
  await waitForPageLoad(page);
}

export function generateTestData() {
  const timestamp = Date.now();
  return {
    email: `test${timestamp}@example.com`,
    searchTerm: 'AWS Lambda',
    randomString: Math.random().toString(36).substring(7),
  };
}
