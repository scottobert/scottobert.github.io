# National Parks Map Feature

## Overview

This feature provides an interactive, pan/zoom/scrollable map displaying all 63 US National Parks. Parks that have been visited are marked with a green checkmark, while unvisited parks are shown with gray markers.

## Components

### Content File
- **Location**: `content/national-parks.md`
- **Type**: `national-parks`
- Contains the page title, description, and introductory text

### Layout
- **Location**: `themes/engineering-pro/layouts/national-parks/single.html`
- Custom Hugo layout that includes:
  - Page header and content
  - Map container div
  - Leaflet.js CSS and JavaScript includes
  - Custom map initialization script

### JavaScript
- **Location**: `static/js/national-parks-map.js`
- Contains:
  - Complete dataset of all 63 US National Parks with coordinates
  - Map initialization using Leaflet.js
  - Custom marker styling for visited/unvisited parks
  - Popup functionality showing park name and state
  - Responsive styling

## Updating Visited Parks

To mark parks as visited, edit `static/js/national-parks-map.js`:

1. Find the park in the `nationalParks` array
2. Change `visited: false` to `visited: true`

Example:
```javascript
{ name: "Yosemite", lat: 37.8651, lng: -119.5383, state: "California", visited: true },
```

## Features

- **Interactive Map**: Pan, zoom, and scroll using mouse or touch
- **Custom Markers**: 
  - Green pins with checkmarks for visited parks
  - Gray pins for unvisited parks
- **Popups**: Click any marker to see park name, state, and visit status
- **Responsive**: Works on desktop and mobile devices
- **Accessible**: Can be navigated via the main menu

## Navigation

The National Parks map is accessible from the main navigation menu at `/national-parks/`.

## Technology Stack

- **Mapping Library**: Leaflet.js 1.9.4
- **Map Tiles**: OpenStreetMap
- **Custom CSS**: Inline styles for markers and popups
- **Hugo**: Static site generation

## Future Enhancements

Potential improvements could include:
- Photo gallery integration for visited parks
- Date visited tracking
- Search/filter functionality
- Statistics (parks visited, states covered, etc.)
- Links to official park websites
- Travel notes or descriptions
