# Engineering Pro Hugo Theme

A professional, engineering-inspired Hugo theme with a focus on clean typography, technical content, and developer-friendly features.

## Features

- Monospace post content for technical clarity
- Custom breadcrumbs and series navigation
- Social sharing (standard, floating, and quick-share options)
- Image gallery shortcode for easy photo collections
- PlantUML diagram shortcode for architecture diagrams
- Responsive design and accessible navigation
- Pagination and sidebar with recent posts and series
- Customizable theme color and layout options

## Usage

1. Add `engineering-pro` to your Hugo site's `themes/` directory.
2. Set `theme = "engineering-pro"` in your `config.toml`.
3. Use the provided shortcodes and partials in your content and layouts.

### Shortcodes

- `{{< image src="image.png" alt="Alt text" caption="Optional caption" width="800" >}}` — Display and process images with Hugo's built-in image processing. Supports automatic resizing, lazy loading, and responsive images.
- `{{< image-gallery gallery_dir="/album" >}}` — Display an image gallery from a static directory.
- `{{< plantuml id="diagram-id" >}} ...PlantUML code... {{< /plantuml >}}` — Render PlantUML diagrams inline.

### Custom Partials

- `breadcrumbs.html` — Renders breadcrumbs for navigation.
- `series-navigation.html` — Adds navigation for post series.
- `social-share.html`, `floating-social-share.html`, `quick-social-share.html` — Multiple social sharing UI options.

## Image Processing

The theme includes an `image` shortcode that leverages Hugo's built-in image processing capabilities:

**Basic usage:**
```markdown
{{< image src="my-image.png" alt="Description" >}}
```

**With caption and custom width:**
```markdown
{{< image src="diagram.png" alt="Architecture diagram" caption="System overview showing microservices architecture" width="600" >}}
```

**Parameters:**
- `src` (required): Image filename (must be in the same directory as the content file for processing)
- `alt` (required): Alt text for accessibility
- `caption` (optional): Caption displayed below the image
- `width` (optional): Maximum width in pixels (default: 800)
- `height` (optional): Maximum height in pixels (auto if not specified)
- `class` (optional): Additional CSS classes

The shortcode automatically handles:
- Image resizing and optimization
- Lazy loading
- Responsive images
- Proper semantic markup with `<figure>` and `<figcaption>`

## Contributing

- Document any new features or changes in this README.
- Add comments to layouts, partials, and shortcodes describing their purpose.
- Prefer TypeScript for new scripts and Playwright for tests.

## License

MIT
