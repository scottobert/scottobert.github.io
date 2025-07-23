# Stylesheet Organization and Hugo Pipes Integration

This theme now uses SCSS for its main stylesheet, located at `assets/css/style.scss`. SCSS features such as variables, mixins, and nesting are used to reduce repetition and improve maintainability.

Hugo Pipes automatically compiles, minifies, and fingerprints the stylesheet. The output is referenced in `baseof.html` via:

```
{{ $style := resources.Get "css/style.scss" | resources.ToCSS | resources.Minify | resources.Fingerprint }}
<link rel="stylesheet" href="{{ $style.Permalink }}">
```

No manual CSS compilation is required. To update styles, edit `style.scss` and use SCSS features to keep code DRY and modular.

For more details, see the theme README.md.
