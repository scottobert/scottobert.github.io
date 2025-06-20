- When adding a new feature to the `engineering-pro` theme, document the feature in a `README.md` file within the theme directory. If the file does not exist, create it and provide a summary of the theme and its features.
- For any changes to Hugo layouts, partials, or archetypes, include a comment in the relevant file describing the purpose of the change.
- When creating or updating content in `content/posts`, ensure each post uses the front matter format found in existing posts and follows the established writing style.
- For static assets (images, CSS, JS), place them in the appropriate subdirectory under `static/` or `themes/engineering-pro/static/` and update references in layouts or content as needed.
- When adding or updating end-to-end or integration tests in the `tests/` directory, use Playwright and TypeScript, and keep test helpers in `tests/utils/`.
- For any new configuration or documentation files, provide a brief description at the top of the file explaining its purpose.
- When updating the site configuration (`config.toml`), ensure changes are compatible with the Hugo version in use and document any breaking changes.
- Always use meaningful commit messages that describe the intent of the change.
- Prefer TypeScript for all new scripts and tests.
- When adding new Hugo shortcodes or custom logic, document their usage in a `USAGE.md` or in the theme's `README.md`.
- When writing new content, limit the usage of lists, use paragraph-style prose where possible, and ensure the content is clear and concise.

## Creating New Blog Posts

When creating a new blog post, follow these specific guidelines:

### File Creation and Naming

- Use the Hugo task "Hugo: New Post" or run `hugo new posts/post-name.md` to create a new post with the archetype template.
- Name files using lowercase with hyphens (kebab-case): `aws-lambda-typescript.md`, `api-design-patterns.md`.
- Place all blog posts in `content/posts/` directory.

### Front Matter Requirements

Every blog post must include the following front matter structure:

```yaml
---
title: "Your Post Title Here"
date: YYYY-MM-DDTHH:MM:SS-07:00
draft: false
categories: ["Primary Category", "Secondary Category"]
tags:
- Tag1
- Tag2
- Tag3
series: "Series Name" # Optional, only if part of a series
---
```

### Front Matter Guidelines

- **Title**: Use title case and be descriptive but concise.
- **Date**: Use the ISO 8601 format with Mountain Time zone (-07:00).
- **Draft**: Set to `false` when ready to publish, `true` for work-in-progress.
- **Categories**: Use 1-2 broad categories from existing ones like "Cloud Computing", "Software Development", "Architecture and Design", "Development Tutorials".
- **Tags**: Include 3-6 specific, relevant tags related to technologies, frameworks, or concepts covered.
- **Series**: Only include if the post is part of a multi-part series. Use existing series names or create new ones consistently.

### Content Structure and Style

- Start with a strong introductory paragraph that explains what the post covers and why it matters.
- Use paragraph-style prose rather than excessive bullet points or lists.
- Include practical code examples when relevant, using proper syntax highlighting.
- Use the PlantUML shortcode for architecture diagrams: `{{< plantuml id="unique-id" >}} ...diagram code... {{< /plantuml >}}`.
- Structure content with clear headings (H2, H3) for easy navigation.
- End with actionable takeaways or next steps.

### Technical Content Standards

- Always use TypeScript for new code examples when applicable.
- Follow AWS SDK v3 patterns for AWS-related content.
- Include error handling and best practices in code examples.
- Provide context and explanation for code snippets rather than just showing code.
- Reference official documentation and authoritative sources when appropriate.

### Example Post Creation Workflow

1. Run the Hugo task "Hugo: New Post" or `hugo new posts/your-post-name.md`
2. Update the front matter with appropriate title, categories, tags, and series (if applicable)
3. Write the content following the style guidelines above
4. Test locally using "Hugo: Serve (Development)" task
5. Set `draft: false` when ready to publish
