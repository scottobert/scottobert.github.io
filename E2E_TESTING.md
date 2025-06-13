# End-to-End Testing Setup

This document describes the comprehensive E2E testing setup for Scott Obert's technical blog.

## Overview

The testing suite uses **Playwright** for end-to-end testing, providing comprehensive coverage of:

- Homepage functionality
- Blog post navigation and content
- Search functionality
- Performance and accessibility
- Cross-browser compatibility
- Mobile responsiveness

## Prerequisites

- Node.js 18 or later
- Hugo (latest version)
- Git

## Setup Instructions

### 1. Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Install Playwright browsers
npx playwright install
```

### 2. Local Development

```bash
# Start Hugo development server
npm run serve

# Run tests (in another terminal)
npm test

# Run tests with UI mode (interactive)
npm run test:ui

# Run tests in headed mode (see browser)
npm run test:headed

# Debug tests
npm run test:debug
```

### 3. View Test Reports

```bash
# Show latest test report
npm run test:report
```

## Test Structure

### Test Files

- **`homepage.spec.ts`**: Tests homepage loading, SEO, and responsiveness
- **`blog-posts.spec.ts`**: Tests blog post navigation, content, and RSS feed
- **`navigation.spec.ts`**: Tests site navigation, breadcrumbs, and keyboard accessibility
- **`search.spec.ts`**: Tests search functionality and JSON index
- **`performance-accessibility.spec.ts`**: Tests performance, accessibility, and semantic HTML

### Utilities

- **`page-objects.ts`**: Page Object Model for maintainable test code
- **`helpers.ts`**: Utility functions for common test operations

## Browser Coverage

Tests run on:
- **Desktop**: Chrome, Firefox, Safari
- **Mobile**: Chrome (Pixel 5), Safari (iPhone 12)

## CI/CD Integration

### GitHub Actions

The `.github/workflows/e2e-tests.yml` workflow runs:
- On push to main/master/develop branches
- On pull requests
- Daily at 6 AM UTC (scheduled)

### Lighthouse Integration

Performance and accessibility auditing with Lighthouse:
- Performance score: minimum 80%
- Accessibility score: minimum 90%
- Best practices: minimum 80%
- SEO: minimum 90%

## Running Tests Locally

### Quick Test Run
```bash
npm test
```

### Run Specific Test File
```bash
npx playwright test homepage.spec.ts
```

### Run Tests on Specific Browser
```bash
npx playwright test --project=chromium
npx playwright test --project=firefox
npx playwright test --project=webkit
```

### Run Tests on Mobile
```bash
npx playwright test --project="Mobile Chrome"
npx playwright test --project="Mobile Safari"
```

## Configuration

### Playwright Config (`playwright.config.ts`)

Key settings:
- **Base URL**: `http://localhost:1313`
- **Parallel execution**: Enabled for faster test runs
- **Retries**: 2 retries on CI, 0 locally
- **Screenshots**: On failure only
- **Video**: On retry with failures
- **Trace**: On first retry

### Web Server Integration

Tests automatically start Hugo server before running and shut it down after completion.

## Best Practices

### Writing Tests

1. **Use Page Object Model**: Encapsulate page interactions in page objects
2. **Wait for Elements**: Use `await expect(element).toBeVisible()` instead of arbitrary timeouts
3. **Descriptive Test Names**: Use clear, descriptive test names
4. **Group Related Tests**: Use `test.describe()` blocks
5. **Clean Test Data**: Each test should be independent

### Example Test Structure

```typescript
import { test, expect } from '@playwright/test';
import { HomePage } from './utils/page-objects';

test.describe('Feature Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should perform specific action', async ({ page }) => {
    const homePage = new HomePage(page);
    await homePage.expectToBeLoaded();
    
    // Test specific functionality
    await expect(page.locator('selector')).toBeVisible();
  });
});
```

## Troubleshooting

### Common Issues

1. **Tests failing locally but passing in CI**
   - Check Hugo version compatibility
   - Ensure all dependencies are installed
   - Check port availability (1313)

2. **Slow test execution**
   - Use `--workers=1` to run tests sequentially
   - Check network conditions
   - Consider reducing test scope

3. **Browser installation issues**
   - Run `npx playwright install --with-deps`
   - Check system requirements

### Debugging

1. **Visual debugging**:
   ```bash
   npm run test:debug
   ```

2. **Run with headed browser**:
   ```bash
   npm run test:headed
   ```

3. **Take screenshots**:
   ```bash
   npx playwright test --screenshot=on
   ```

## Maintenance

### Regular Tasks

1. **Update dependencies**: Run `npm update` monthly
2. **Review test coverage**: Ensure new features have tests
3. **Performance monitoring**: Monitor Lighthouse scores
4. **Accessibility compliance**: Regular accessibility audits

### Adding New Tests

When adding new features to the website:

1. Create or update relevant test files
2. Follow existing naming conventions
3. Add page objects for new pages
4. Update documentation
5. Test locally before committing

## Performance Benchmarks

Target metrics:
- **Load time**: < 3 seconds
- **First Contentful Paint**: < 1.5 seconds
- **Lighthouse Performance**: > 80
- **Lighthouse Accessibility**: > 90

## Resources

- [Playwright Documentation](https://playwright.dev/)
- [Lighthouse Documentation](https://developers.google.com/web/tools/lighthouse)
- [Hugo Documentation](https://gohugo.io/documentation/)
- [Web Accessibility Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
